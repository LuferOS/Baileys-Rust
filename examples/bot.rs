use baileys_rs::proto::message::ExtendedTextMessage;
use baileys_rs::proto::Message;
use baileys_rs::signal::LibSignalRepository;
use baileys_rs::socket::{MessagesRecvSocket, MessagesSocket, RecvEvent, WaSocket};
use baileys_rs::types::{
    AuthenticationCreds, ConnectionState, DisconnectReason, SocketConfig, SocketEvent,
    WaPresence,
};
use baileys_rs::utils::{
    fetch_latest_wa_web_version, normalize_message_content, use_multi_file_auth_state,
    AnyMessageContent, Browsers, MessageGenerationOptions,
};
use baileys_rs::wa_binary::{
    BinaryNode, BinaryNodeAttributes, BinaryNodeData, S_WHATSAPP_NET,
};
use qrcode::render::unicode;
use qrcode::QrCode;
use std::borrow::Borrow;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn read_ram_mb() -> (f64, f64, u32) {
    let mut rss_kb = 0u64;
    let mut hwm_kb = 0u64;
    let mut threads = 0u32;

    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("VmRSS:") {
                rss_kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("VmHWM:") {
                hwm_kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:") {
                threads = v
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u32>().ok())
                    .unwrap_or(0);
            }
        }
    }

    (rss_kb as f64 / 1024.0, hwm_kb as f64 / 1024.0, threads)
}

fn extract_text(msg: &Message) -> Option<String> {
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

async fn save_creds(auth_dir: &Path, creds: &AuthenticationCreds) {
    let _ = tokio::fs::create_dir_all(auth_dir).await;
    if let Ok(bytes) = serde_json::to_vec_pretty(creds) {
        let _ = tokio::fs::write(auth_dir.join("creds.json"), bytes).await;
    }
}

async fn ping_wa_ms(socket: &WaSocket) -> Option<f64> {
    let t0 = Instant::now();
    let iq = BinaryNode {
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
    socket
        .query(iq, Some(3_000))
        .await
        .ok()
        .map(|_| t0.elapsed().as_secs_f64() * 1000.0)
}

fn format_info(
    started_at: Instant,
    wa_version: [u32; 3],
    ping_ms: Option<f64>,
    proc_ms: f64,
    msg_count: u64,
) -> String {
    let (rss, hwm, threads) = read_ram_mb();
    let secs = started_at.elapsed().as_secs();
    let ping_str = ping_ms
        .map(|ms| format!("{:.2} ms", ms))
        .unwrap_or_else(|| "N/A".to_string());

    format!(
        "*Baileys-Rust Example Bot v{}*\n\
        Ping WA: {}\n\
        Respuesta local: {:.3} ms\n\
        RAM: {:.2} MB (pico {:.2} MB) | Hilos: {}\n\
        Rust: {}\n\
        Plataforma: {}/{}\n\
        WA Web: {}.{}.{}\n\
        Uptime: {:02}h {:02}m {:02}s | Mensajes: {}\n\
        Modulos: WABinary, WAProto, Noise XX, Signal E2EE, Groups, Communities, Newsletter, Mex, Business, Media, AppState LTHash, WAM",
        env!("CARGO_PKG_VERSION"),
        ping_str,
        proc_ms,
        rss,
        hwm,
        threads,
        env!("BAILEYS_RUSTC_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        wa_version[0],
        wa_version[1],
        wa_version[2],
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        msg_count
    )
}

fn print_qr(qr: &str) {
    if let Ok(code) = QrCode::new(qr.as_bytes()) {
        let rendered = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .quiet_zone(true)
            .build();
        println!("\n{}\n", rendered);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_dir = Path::new("auth_info_bot");
    let started_at = Instant::now();
    let msg_counter = Arc::new(AtomicU64::new(0));
    let wa_ver = fetch_latest_wa_web_version(Some(10_000)).await;

    loop {
        let auth = Arc::new(use_multi_file_auth_state(auth_dir).await?);
        let mut config = SocketConfig::default();
        config.version = wa_ver.version;
        config.browser = Browsers::macos("Chrome");

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

        let msg_sock = Arc::clone(&messages);
        let counter = Arc::clone(&msg_counter);
        let version = wa_ver.version;
        let recv_task = tokio::spawn(async move {
            while let Ok(event) = recv_rx.recv().await {
                if let RecvEvent::MessageUpsert {
                    message,
                    is_offline,
                } = event
                {
                    let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if is_offline {
                        continue;
                    }
                    let Some(ref proto_msg) = message.message else {
                        continue;
                    };
                    let Some(text) = extract_text(proto_msg) else {
                        continue;
                    };
                    if text.trim().eq_ignore_ascii_case(".info") {
                        let Some(jid) = message.key.remote_jid.clone() else {
                            continue;
                        };
                        let t0 = Instant::now();
                        let ping = ping_wa_ms(&msg_sock.socket).await;
                        let creds = msg_sock.socket.creds().await;
                        let me = creds.me.as_ref().map(|m| m.id.clone());
                        let reply = format_info(
                            started_at,
                            version,
                            ping,
                            t0.elapsed().as_secs_f64() * 1000.0,
                            total,
                        );
                        let opts = MessageGenerationOptions {
                            user_jid: me,
                            message_id: None,
                            timestamp: None,
                            quoted: Some(Box::new(message)),
                            ephemeral_expiration: None,
                            mentions: Vec::new(),
                            view_once: false,
                            edit: None,
                            context_info: None,
                            background_color: None,
                            font: None,
                        };
                        let _ = msg_sock
                            .send_message(&jid, AnyMessageContent::Text(reply), opts)
                            .await;
                    }
                }
            }
        });

        let mut reconnect = false;
        while let Ok(ev) = socket_rx.recv().await {
            match ev {
                SocketEvent::ConnectionUpdate(upd) => {
                    if let Some(qr) = upd.qr {
                        print_qr(&qr);
                    }
                    if let Some(ConnectionState::Open) = upd.connection {
                        println!("Bot listo. Envia '.info' desde cualquier chat.");
                        let _ = messages
                            .socket
                            .send_presence_update(WaPresence::Available, None)
                            .await;
                    }
                    if let Some(ConnectionState::Close) = upd.connection {
                        let code = upd.last_disconnect.and_then(|d| d.status_code);
                        reconnect = code != Some(DisconnectReason::LoggedOut as u16);
                        break;
                    }
                }
                SocketEvent::CredsUpdate(creds) => {
                    save_creds(auth_dir, &creds).await;
                }
                SocketEvent::Node(node) => {
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
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    Ok(())
}
