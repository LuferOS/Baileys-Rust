use baileys_rs::proto::message::ExtendedTextMessage;
use baileys_rs::proto::Message;
use baileys_rs::signal::LibSignalRepository;
use baileys_rs::socket::{MessagesRecvSocket, MessagesSocket, RecvEvent, WaSocket};
use baileys_rs::types::{
    AuthenticationCreds, ConnectionState, DisconnectReason, SocketConfig, SocketEvent, WaMessage,
    WaPresence,
};
use baileys_rs::utils::{
    fetch_latest_wa_web_version, get_next_pre_keys_node, normalize_message_content,
    unix_timestamp_seconds, use_multi_file_auth_state, AnyMessageContent, Browsers,
    MessageGenerationOptions,
};
use baileys_rs::wa_binary::{
    BinaryNode, BinaryNodeAttributes, BinaryNodeData, S_WHATSAPP_NET,
};
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ACTIVE_MODULES: &[&str] = &[
    "WABinary (Codec + JIDs)",
    "WAProto (Prost Protobuf)",
    "Noise XX + TLS (rustls + ring)",
    "Signal E2EE (1:1 + SenderKey + LID)",
    "Socket (Chats, Groups, Communities)",
    "Newsletter + Mex GraphQL",
    "Business & Catalog",
    "Media (AES-CBC + HMAC + Upload/Download)",
    "AppState Sync (LTHash + History + EventBuffer)",
    "WAM v5 Telemetry Encoder",
];

#[derive(Serialize, Deserialize)]
struct CachedWaVersion {
    version: [u32; 3],
    updated_at: u64,
}

async fn resolve_wa_version(auth_dir: &Path) -> ([u32; 3], bool) {
    let cache_path = auth_dir.join("wa_version.json");
    let now = unix_timestamp_seconds();

    if let Ok(bytes) = tokio::fs::read(&cache_path).await {
        if let Ok(cached) = serde_json::from_slice::<CachedWaVersion>(&bytes) {
            if now.saturating_sub(cached.updated_at) < 86_400 {
                return (cached.version, true);
            }
        }
    }

    let fetched = fetch_latest_wa_web_version(Some(2_500)).await;
    if fetched.is_latest {
        let _ = tokio::fs::create_dir_all(auth_dir).await;
        if let Ok(json) = serde_json::to_vec(&CachedWaVersion {
            version: fetched.version,
            updated_at: now,
        }) {
            let _ = tokio::fs::write(&cache_path, json).await;
        }
    }
    (fetched.version, fetched.is_latest)
}

struct ProcessStats {
    rss_mb: f64,
    hwm_mb: f64,
    threads: u32,
}

fn read_process_stats() -> ProcessStats {
    let mut rss_kb = 0u64;
    let mut hwm_kb = 0u64;
    let mut threads = 0u32;

    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                hwm_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                threads = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
            }
        }
    }

    ProcessStats {
        rss_mb: rss_kb as f64 / 1024.0,
        hwm_mb: hwm_kb as f64 / 1024.0,
        threads,
    }
}

fn format_uptime(dur: Duration) -> String {
    let secs = dur.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}h {:02}m {:02}s", h, m, s)
}

fn render_qr_terminal(qr_data: &str) {
    match QrCode::new(qr_data.as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .quiet_zone(true)
                .build();
            println!("\nEscanea este codigo QR en WhatsApp -> Dispositivos vinculados:\n");
            println!("{}", rendered);
        }
        Err(err) => {
            eprintln!("Error renderizando QR: {}", err);
            println!("QR raw: {}", qr_data);
        }
    }
}

fn extract_message_text(msg: &Message) -> Option<String> {
    let norm = normalize_message_content(msg);
    if let Some(ref text) = norm.conversation {
        if !text.is_empty() {
            return Some(text.clone());
        }
    }
    if let Some(ref ext) = norm.extended_text_message {
        let inner: &ExtendedTextMessage = Borrow::borrow(ext);
        if let Some(ref text) = inner.text {
            if !text.is_empty() {
                return Some(text.clone());
            }
        }
    }
    None
}

async fn save_creds_to_disk(
    auth_dir: &Path,
    creds: &AuthenticationCreds,
) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(auth_dir).await?;
    let bytes = serde_json::to_vec_pretty(creds)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tokio::fs::write(auth_dir.join("creds.json"), bytes).await
}

async fn measure_wa_ping_ms(socket: &WaSocket) -> Option<f64> {
    let start = Instant::now();
    let ping_iq = BinaryNode {
        tag: "iq".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
            ("type".to_string(), "get".to_string()),
            ("xmlns".to_string(), "w:p".to_string()),
        ]),
        content: Some(BinaryNodeData::List(vec![BinaryNode {
            tag: "ping".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }])),
    };
    match socket.query(ping_iq, Some(3_000)).await {
        Ok(_) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Err(_) => None,
    }
}

async fn activate_session(
    messages: &Arc<MessagesSocket>,
    activated: &AtomicBool,
    auth_dir: &Path,
    connect_started: Instant,
) {
    if activated.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut creds_now = messages.socket.creds().await;
    let prekey_file_exists = auth_dir.join("pre-key-1.json").exists();

    if creds_now.first_unuploaded_pre_key_id <= 1 && !prekey_file_exists {
        let t_pk = Instant::now();
        if let Ok(prekeys_node) = get_next_pre_keys_node(&messages.auth, 30).await {
            if let Err(err) = messages.socket.query(prekeys_node.node, Some(5_000)).await {
                eprintln!("[prekeys] aviso subiendo pre-keys iniciales: {}", err);
            } else {
                creds_now.first_unuploaded_pre_key_id = prekeys_node.update.first_unuploaded_pre_key_id;
                creds_now.next_pre_key_id = prekeys_node.update.next_pre_key_id;
                let _ = save_creds_to_disk(auth_dir, &creds_now).await;
                println!(
                    "[perf] pre-keys subidas en {:.0} ms",
                    t_pk.elapsed().as_secs_f64() * 1000.0
                );
            }
        }
    }

    let t_act = Instant::now();
    if let Err(err) = messages.socket.send_passive_iq(true).await {
        eprintln!("[session] aviso enviando <active/>: {}", err);
    }

    let _ = messages
        .socket
        .send_presence_update(WaPresence::Available, None)
        .await;

    println!(
        "Bot listo como {:?} | active: {:.0} ms | total conexion: {:.0} ms",
        creds_now.me.as_ref().map(|m| &m.id),
        t_act.elapsed().as_secs_f64() * 1000.0,
        connect_started.elapsed().as_secs_f64() * 1000.0
    );
}

fn build_info_reply(
    started_at: Instant,
    wa_version: [u32; 3],
    wa_ping_ms: Option<f64>,
    local_proc_ms: f64,
    processed_msgs: u64,
    me_jid: Option<&str>,
) -> String {
    let stats = read_process_stats();
    let ping_label = match wa_ping_ms {
        Some(ms) => format!("{:.2} ms (IQ w:p)", ms),
        None => "N/A".to_string(),
    };
    let modules_list = ACTIVE_MODULES
        .iter()
        .map(|m| format!("  - {}", m))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "*Baileys-Rust (`baileys-rs` v{})*\n\
        Estado: En linea y operativo\n\
        Cuenta: {}\n\n\
        *Rendimiento*\n\
        - Ping WhatsApp: {}\n\
        - Proceso local: {:.3} ms\n\
        - Uptime: {}\n\
        - Mensajes procesados: {}\n\n\
        *Memoria y Runtime*\n\
        - RAM actual (VmRSS): {:.2} MB\n\
        - RAM pico (VmHWM): {:.2} MB\n\
        - Hilos activos: {}\n\
        - Rust: {}\n\
        - Sistema: {}/{}\n\
        - Protocolo WA Web: {}.{}.{}\n\n\
        *Modulos activos ({})*\n\
        {}\n\n\
        *Comandos*\n\
        - `.info` : Diagnostico del bot en tiempo real",
        env!("CARGO_PKG_VERSION"),
        me_jid.unwrap_or("desconocida"),
        ping_label,
        local_proc_ms,
        format_uptime(started_at.elapsed()),
        processed_msgs,
        stats.rss_mb,
        stats.hwm_mb,
        stats.threads,
        env!("BAILEYS_RUSTC_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        wa_version[0],
        wa_version[1],
        wa_version[2],
        ACTIVE_MODULES.len(),
        modules_list
    )
}

fn make_reply_options(quoted: WaMessage, user_jid: Option<String>) -> MessageGenerationOptions {
    MessageGenerationOptions {
        user_jid,
        message_id: None,
        timestamp: None,
        quoted: Some(Box::new(quoted)),
        ephemeral_expiration: None,
        mentions: Vec::new(),
        view_once: false,
        edit: None,
        context_info: None,
        background_color: None,
        font: None,
    }
}

struct CliArgs {
    auth_dir: PathBuf,
    pair_phone: Option<String>,
    self_test: bool,
}

fn parse_args() -> CliArgs {
    let mut auth_dir = PathBuf::from("auth_info");
    let mut pair_phone: Option<String> = std::env::var("PAIR_NUMBER").ok();
    let mut self_test = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--auth" if i + 1 < args.len() => {
                auth_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--pair" if i + 1 < args.len() => {
                pair_phone = Some(args[i + 1].clone());
                i += 2;
            }
            "--self-test" => {
                self_test = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    CliArgs {
        auth_dir,
        pair_phone: pair_phone.map(|p| p.chars().filter(|c| c.is_ascii_digit()).collect()),
        self_test,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_args();
    let started_at = Instant::now();
    let processed_msgs = Arc::new(AtomicU64::new(0));

    let t_ver = Instant::now();
    let (wa_version, is_latest) = resolve_wa_version(&cli.auth_dir).await;
    println!(
        "baileys-rs v{} | WA Web {}.{}.{} (latest={}, {:.0} ms)",
        env!("CARGO_PKG_VERSION"),
        wa_version[0],
        wa_version[1],
        wa_version[2],
        is_latest,
        t_ver.elapsed().as_secs_f64() * 1000.0
    );

    if cli.self_test {
        let local_start = Instant::now();
        let report = build_info_reply(
            started_at,
            wa_version,
            None,
            local_start.elapsed().as_secs_f64() * 1000.0,
            0,
            Some("self-test@local"),
        );
        println!("\n{}", report);
        return Ok(());
    }

    loop {
        let connect_started = Instant::now();
        let auth = Arc::new(use_multi_file_auth_state(&cli.auth_dir).await?);
        let registered = auth.creds.registered;

        let mut config = SocketConfig::default();
        config.version = wa_version;
        config.browser = Browsers::macos("Chrome");
        config.mark_online_on_connect = true;

        println!("Conectando a WhatsApp Web...");
        let socket = WaSocket::connect(config, auth.creds.clone()).await?;
        println!(
            "[perf] ws+noise listo en {:.0} ms",
            connect_started.elapsed().as_secs_f64() * 1000.0
        );

        let signal_repo = Arc::new(LibSignalRepository::new(Arc::clone(&auth), None));
        let messages = Arc::new(MessagesSocket::new(
            socket,
            Arc::clone(&auth),
            Arc::clone(&signal_repo),
        ));
        let recv = Arc::new(MessagesRecvSocket::new(Arc::clone(&messages)));

        let mut socket_rx = messages.socket.subscribe();
        let mut recv_rx = recv.subscribe();
        let activated = Arc::new(AtomicBool::new(false));

        if registered {
            let msg_ref = Arc::clone(&messages);
            let act_ref = Arc::clone(&activated);
            let dir_ref = cli.auth_dir.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                if msg_ref.socket.is_open() {
                    activate_session(&msg_ref, &act_ref, &dir_ref, connect_started).await;
                }
            });
        } else if let Some(ref phone) = cli.pair_phone {
            if !phone.is_empty() {
                let msg_ref = Arc::clone(&messages);
                let phone_clone = phone.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    match msg_ref.socket.request_pairing_code(&phone_clone, None).await {
                        Ok(code) => {
                            let formatted = if code.len() == 8 {
                                format!("{}-{}", &code[..4], &code[4..])
                            } else {
                                code
                            };
                            println!("\nCodigo de vinculacion (Pairing Code): {}\n", formatted);
                        }
                        Err(err) => {
                            eprintln!("Error solicitando pairing code: {}", err);
                        }
                    }
                });
            }
        }

        let msg_handler_socket = Arc::clone(&messages);
        let msg_counter = Arc::clone(&processed_msgs);
        let handler_task = tokio::spawn(async move {
            while let Ok(event) = recv_rx.recv().await {
                if let RecvEvent::MessageUpsert {
                    message,
                    is_offline,
                } = event
                {
                    let count = msg_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if is_offline {
                        continue;
                    }
                    let Some(ref proto_msg) = message.message else {
                        continue;
                    };
                    let Some(text) = extract_message_text(proto_msg) else {
                        continue;
                    };
                    println!(
                        "[msg] chat={:?} from_me={:?} text={:?}",
                        message.key.remote_jid, message.key.from_me, text
                    );
                    if text.trim().eq_ignore_ascii_case(".info") {
                        let Some(remote_jid) = message.key.remote_jid.clone() else {
                            continue;
                        };
                        let cmd_start = Instant::now();
                        let wa_ping = measure_wa_ping_ms(&msg_handler_socket.socket).await;
                        let creds_now = msg_handler_socket.socket.creds().await;
                        let me_jid = creds_now.me.as_ref().map(|m| m.id.clone());
                        let local_ms = cmd_start.elapsed().as_secs_f64() * 1000.0;

                        let reply = build_info_reply(
                            started_at,
                            wa_version,
                            wa_ping,
                            local_ms,
                            count,
                            me_jid.as_deref(),
                        );

                        let send_start = Instant::now();
                        let opts = make_reply_options(message, me_jid);
                        match msg_handler_socket
                            .send_message(&remote_jid, AnyMessageContent::Text(reply), opts)
                            .await
                        {
                            Ok(_) => {
                                println!(
                                    "[.info] respondido a {} en {:.2} ms",
                                    remote_jid,
                                    send_start.elapsed().as_secs_f64() * 1000.0
                                );
                            }
                            Err(err) => {
                                eprintln!("[.info] error enviando respuesta: {}", err);
                            }
                        }
                    }
                }
            }
        });

        let mut should_reconnect = false;
        let pairing_mode = cli.pair_phone.as_ref().is_some_and(|p| !p.is_empty());

        while let Ok(ev) = socket_rx.recv().await {
            match ev {
                SocketEvent::ConnectionUpdate(update) => {
                    if let Some(qr) = update.qr {
                        if !pairing_mode {
                            render_qr_terminal(&qr);
                        }
                    }
                    if let Some(state) = update.connection {
                        match state {
                            ConnectionState::Connecting => {}
                            ConnectionState::Open => {
                                let msg_ref = Arc::clone(&messages);
                                let act_ref = Arc::clone(&activated);
                                let dir_ref = cli.auth_dir.clone();
                                tokio::spawn(async move {
                                    activate_session(&msg_ref, &act_ref, &dir_ref, connect_started)
                                        .await;
                                });
                            }
                            ConnectionState::Close => {
                                let code = update.last_disconnect.as_ref().and_then(|d| d.status_code);
                                let err_msg = update
                                    .last_disconnect
                                    .as_ref()
                                    .and_then(|d| d.error.as_deref())
                                    .unwrap_or("sin detalle");
                                println!("Conexion cerrada (codigo={:?}, motivo={})", code, err_msg);

                                if code == Some(DisconnectReason::LoggedOut as u16) {
                                    println!(
                                        "Sesion cerrada desde el telefono. Elimina {:?} y vuelve a vincular.",
                                        cli.auth_dir
                                    );
                                    should_reconnect = false;
                                } else {
                                    should_reconnect = true;
                                }
                                break;
                            }
                        }
                    }
                }
                SocketEvent::CredsUpdate(new_creds) => {
                    if let Err(err) = save_creds_to_disk(&cli.auth_dir, &new_creds).await {
                        eprintln!("Error guardando creds.json: {}", err);
                    }
                }
                SocketEvent::Node(node) => {
                    let recv_clone = Arc::clone(&recv);
                    tokio::spawn(async move {
                        if let Err(err) = recv_clone.process_node(&node).await {
                            eprintln!("Error procesando nodo <{}>: {}", node.tag, err);
                        }
                    });
                }
            }
        }

        handler_task.abort();

        if !should_reconnect {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    Ok(())
}
