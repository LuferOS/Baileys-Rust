mod cmd;
mod handler;

use baileys_rs::signal::LibSignalRepository;
use baileys_rs::socket::{MessagesRecvSocket, MessagesSocket, RecvEvent, WaSocket};
use baileys_rs::types::{
    AuthenticationCreds, ConnectionState, DisconnectReason, SocketConfig, SocketEvent, WaPresence,
};
use baileys_rs::utils::{
    fetch_latest_wa_web_version, get_next_pre_keys_node, unix_timestamp_seconds,
    use_multi_file_auth_state, Browsers,
};
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const BOT_NAME: &str = "Aura-Reed Rust";

#[derive(Serialize, Deserialize)]
struct CachedWaVersion {
    version: [u32; 3],
    updated_at: u64,
}

pub struct AuraConfig {
    pub auth_dir: PathBuf,
    pub pair_phone: Option<String>,
    pub prefixes: Vec<String>,
    pub worker_threads: usize,
}

pub struct BotContext {
    pub started_at: Instant,
    pub wa_version: [u32; 3],
    pub processed_msgs: Arc<AtomicU64>,
    pub prefixes: Vec<String>,
    pub worker_threads: usize,
}

fn detected_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .max(4)
}

fn parse_aura_config() -> AuraConfig {
    let mut auth_dir = PathBuf::from("auth_info_aura");
    let mut pair_phone: Option<String> = std::env::var("PAIR_NUMBER").ok();
    let mut prefixes = vec![".".to_string(), "/".to_string()];
    let mut worker_threads = std::env::var("AURA_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or_else(detected_cores);

    if let Ok(env_prefix) = std::env::var("AURA_PREFIX") {
        let parsed: Vec<String> = env_prefix
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !parsed.is_empty() {
            prefixes = parsed;
        }
    }

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
            "--threads" if i + 1 < args.len() => {
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    if n >= 1 {
                        worker_threads = n;
                    }
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    AuraConfig {
        auth_dir,
        pair_phone: pair_phone.map(|p| p.chars().filter(|c| c.is_ascii_digit()).collect()),
        prefixes,
        worker_threads,
    }
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

    let fetched = fetch_latest_wa_web_version(Some(2_000)).await;
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

fn render_qr_terminal(qr_data: &str) {
    if let Ok(code) = QrCode::new(qr_data.as_bytes()) {
        let rendered = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .quiet_zone(true)
            .build();
        println!("\nEscanea este QR en WhatsApp -> Dispositivos vinculados:\n");
        println!("{}", rendered);
    }
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
    let prekey_exists = auth_dir.join("pre-key-1.json").exists();

    if creds_now.first_unuploaded_pre_key_id <= 1 && !prekey_exists {
        if let Ok(prekeys_node) = get_next_pre_keys_node(&messages.auth, 30).await {
            if messages
                .socket
                .query(prekeys_node.node, Some(4_000))
                .await
                .is_ok()
            {
                creds_now.first_unuploaded_pre_key_id = prekeys_node.update.first_unuploaded_pre_key_id;
                creds_now.next_pre_key_id = prekeys_node.update.next_pre_key_id;
                let _ = save_creds_to_disk(auth_dir, &creds_now).await;
            }
        }
    }

    let _ = messages.socket.send_passive_iq(true).await;
    let _ = messages
        .socket
        .send_presence_update(WaPresence::Available, None)
        .await;

    println!(
        "[{}] listo como {:?} en {:.0} ms",
        BOT_NAME,
        creds_now.me.as_ref().map(|m| &m.id),
        connect_started.elapsed().as_secs_f64() * 1000.0
    );
}

pub async fn run_aura(cfg: AuraConfig) -> Result<(), Box<dyn std::error::Error>> {
    let (wa_version, _) = resolve_wa_version(&cfg.auth_dir).await;
    let ctx = Arc::new(BotContext {
        started_at: Instant::now(),
        wa_version,
        processed_msgs: Arc::new(AtomicU64::new(0)),
        prefixes: cfg.prefixes.clone(),
        worker_threads: cfg.worker_threads,
    });

    println!(
        "{} v{} | WA Web {}.{}.{} | workers={}",
        BOT_NAME,
        env!("CARGO_PKG_VERSION"),
        wa_version[0],
        wa_version[1],
        wa_version[2],
        cfg.worker_threads
    );

    loop {
        let connect_started = Instant::now();
        let auth = Arc::new(use_multi_file_auth_state(&cfg.auth_dir).await?);
        let registered = auth.creds.registered;

        let mut config = SocketConfig::default();
        config.version = wa_version;
        config.browser = Browsers::macos("Chrome");
        config.mark_online_on_connect = true;
        config.connect_timeout_ms = 8_000;
        config.default_query_timeout_ms = 8_000;

        let socket = WaSocket::connect(config, auth.creds.clone()).await?;
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
            let dir_ref = cfg.auth_dir.clone();
            tokio::spawn(async move {
                for _ in 0..40 {
                    if msg_ref.socket.is_open() {
                        activate_session(&msg_ref, &act_ref, &dir_ref, connect_started).await;
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                activate_session(&msg_ref, &act_ref, &dir_ref, connect_started).await;
            });
        } else if let Some(ref phone) = cfg.pair_phone {
            if !phone.is_empty() {
                let msg_ref = Arc::clone(&messages);
                let phone_clone = phone.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    if let Ok(code) = msg_ref.socket.request_pairing_code(&phone_clone, None).await {
                        let formatted = if code.len() == 8 {
                            format!("{}-{}", &code[..4], &code[4..])
                        } else {
                            code
                        };
                        println!("\nPairing Code: {}\n", formatted);
                    }
                });
            }
        }

        let msg_sock = Arc::clone(&messages);
        let ctx_ref = Arc::clone(&ctx);
        let recv_task = tokio::spawn(async move {
            while let Ok(event) = recv_rx.recv().await {
                if let RecvEvent::MessageUpsert {
                    message,
                    is_offline,
                } = event
                {
                    ctx_ref.processed_msgs.fetch_add(1, Ordering::Relaxed);
                    if is_offline {
                        continue;
                    }
                    let Some(ref proto_msg) = message.message else {
                        continue;
                    };
                    let Some(text) = handler::extract_message_text(proto_msg) else {
                        continue;
                    };
                    if let Some((cmd_name, args)) = handler::parse_command(&text, &ctx_ref.prefixes) {
                        handler::dispatch(&msg_sock, &ctx_ref, message, &cmd_name, &args).await;
                    }
                }
            }
        });

        let mut reconnect = false;
        let pairing_mode = cfg.pair_phone.as_ref().is_some_and(|p| !p.is_empty());

        while let Ok(ev) = socket_rx.recv().await {
            match ev {
                SocketEvent::ConnectionUpdate(upd) => {
                    if let Some(qr) = upd.qr {
                        if !pairing_mode {
                            render_qr_terminal(&qr);
                        }
                    }
                    if let Some(ConnectionState::Open) = upd.connection {
                        let msg_ref = Arc::clone(&messages);
                        let act_ref = Arc::clone(&activated);
                        let dir_ref = cfg.auth_dir.clone();
                        tokio::spawn(async move {
                            activate_session(&msg_ref, &act_ref, &dir_ref, connect_started).await;
                        });
                    }
                    if let Some(ConnectionState::Close) = upd.connection {
                        let code = upd.last_disconnect.as_ref().and_then(|d| d.status_code);
                        reconnect = code != Some(DisconnectReason::LoggedOut as u16);
                        break;
                    }
                }
                SocketEvent::CredsUpdate(creds) => {
                    let _ = save_creds_to_disk(&cfg.auth_dir, &creds).await;
                }
                SocketEvent::Node(node) => {
                    if registered && !activated.load(Ordering::SeqCst) {
                        let msg_ref = Arc::clone(&messages);
                        let act_ref = Arc::clone(&activated);
                        let dir_ref = cfg.auth_dir.clone();
                        tokio::spawn(async move {
                            activate_session(&msg_ref, &act_ref, &dir_ref, connect_started).await;
                        });
                    }
                    let r = Arc::clone(&recv);
                    tokio::spawn(async move {
                        let _ = r.process_node(&node).await;
                    });
                }
            }
        }

        recv_task.abort();
        if !reconnect {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_aura_config();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?;

    runtime.block_on(run_aura(cfg))
}
