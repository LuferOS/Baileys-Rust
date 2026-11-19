mod cmd;
mod debug;
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
use debug::DebugState;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, Semaphore};

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
    pub debug_enabled: bool,
}

pub struct BotContext {
    pub started_at: Instant,
    pub wa_version: [u32; 3],
    pub processed_msgs: Arc<AtomicU64>,
    pub prefixes: Vec<String>,
    pub worker_threads: usize,
    pub debug: Arc<DebugState>,
    pub cmd_semaphore: Arc<Semaphore>,
    pub creds_lock: Arc<Mutex<()>>,
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
    let mut debug_enabled = std::env::var("AURA_DEBUG")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));

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
            "--debug" => {
                debug_enabled = true;
                i += 1;
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
        debug_enabled,
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

async fn save_creds_atomic(
    auth_dir: &Path,
    creds: &AuthenticationCreds,
    lock: &Mutex<()>,
) -> Result<(), std::io::Error> {
    let _guard = lock.lock().await;
    tokio::fs::create_dir_all(auth_dir).await?;
    let bytes = serde_json::to_vec_pretty(creds)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp_path = auth_dir.join("creds.json.tmp");
    let final_path = auth_dir.join("creds.json");
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, &final_path).await
}

async fn activate_session(
    messages: &Arc<MessagesSocket>,
    ctx: &Arc<BotContext>,
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
                let _ = save_creds_atomic(auth_dir, &creds_now, &ctx.creds_lock).await;
            }
        }
    }

    let _ = tokio::join!(
        messages.socket.send_passive_iq(true),
        messages.socket.send_presence_update(WaPresence::Available, None)
    );

    let warm_msg = Arc::clone(messages);
    let warm_dbg = Arc::clone(&ctx.debug);
    tokio::spawn(async move {
        let t = Instant::now();
        if warm_msg.refresh_media_conn(false).await.is_ok() {
            warm_dbg.log(
                "warmup",
                format!("media_conn pre-cargado en {:.0} ms", t.elapsed().as_secs_f64() * 1000.0),
            );
        }
    });

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
        debug: Arc::new(DebugState::new(cfg.debug_enabled)),
        cmd_semaphore: Arc::new(Semaphore::new(64)),
        creds_lock: Arc::new(Mutex::new(())),
    });

    println!(
        "{} v{} | WA Web {}.{}.{} | workers={} | debug={}",
        BOT_NAME,
        env!("CARGO_PKG_VERSION"),
        wa_version[0],
        wa_version[1],
        wa_version[2],
        cfg.worker_threads,
        if cfg.debug_enabled { "ON" } else { "OFF" }
    );

    let mut backoff_ms: u64 = 250;

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

        let socket = match WaSocket::connect(config, auth.creds.clone()).await {
            Ok(s) => s,
            Err(err) => {
                ctx.debug
                    .record_error("connect", format!("{}", err))
                    .await;
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(5_000);
                continue;
            }
        };

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
            let ctx_ref = Arc::clone(&ctx);
            let act_ref = Arc::clone(&activated);
            let dir_ref = cfg.auth_dir.clone();
            tokio::spawn(async move {
                for _ in 0..40 {
                    if msg_ref.socket.is_open() {
                        activate_session(&msg_ref, &ctx_ref, &act_ref, &dir_ref, connect_started).await;
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                activate_session(&msg_ref, &ctx_ref, &act_ref, &dir_ref, connect_started).await;
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
            loop {
                match recv_rx.recv().await {
                    Ok(RecvEvent::MessageUpsert {
                        message,
                        is_offline,
                    }) => {
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
                            let sock_clone = Arc::clone(&msg_sock);
                            let ctx_clone = Arc::clone(&ctx_ref);
                            tokio::spawn(async move {
                                let Ok(_permit) = ctx_clone.cmd_semaphore.clone().acquire_owned().await else {
                                    return;
                                };
                                ctx_clone.debug.active_tasks.fetch_add(1, Ordering::Relaxed);
                                ctx_clone.debug.total_commands.fetch_add(1, Ordering::Relaxed);
                                let timed = tokio::time::timeout(
                                    Duration::from_secs(25),
                                    handler::dispatch(&sock_clone, &ctx_clone, message, &cmd_name, &args),
                                )
                                .await;
                                if timed.is_err() {
                                    ctx_clone
                                        .debug
                                        .record_error("timeout", format!(".{} excedio 25s", cmd_name))
                                        .await;
                                }
                                ctx_clone.debug.active_tasks.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(skipped)) => {
                        ctx_ref.debug.recv_lagged.fetch_add(skipped, Ordering::Relaxed);
                        ctx_ref
                            .debug
                            .record_error("recv_rx", format!("lagged {} eventos", skipped))
                            .await;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        let mut reconnect = false;
        let pairing_mode = cfg.pair_phone.as_ref().is_some_and(|p| !p.is_empty());

        loop {
            match socket_rx.recv().await {
                Ok(SocketEvent::ConnectionUpdate(upd)) => {
                    if let Some(qr) = upd.qr {
                        if !pairing_mode {
                            render_qr_terminal(&qr);
                        }
                    }
                    if let Some(ConnectionState::Open) = upd.connection {
                        backoff_ms = 250;
                        let msg_ref = Arc::clone(&messages);
                        let ctx_ref = Arc::clone(&ctx);
                        let act_ref = Arc::clone(&activated);
                        let dir_ref = cfg.auth_dir.clone();
                        tokio::spawn(async move {
                            activate_session(&msg_ref, &ctx_ref, &act_ref, &dir_ref, connect_started).await;
                        });
                    }
                    if let Some(ConnectionState::Close) = upd.connection {
                        let code = upd.last_disconnect.as_ref().and_then(|d| d.status_code);
                        ctx.debug
                            .record_error("disconnect", format!("codigo={:?}", code))
                            .await;
                        reconnect = code != Some(DisconnectReason::LoggedOut as u16);
                        break;
                    }
                }
                Ok(SocketEvent::CredsUpdate(creds)) => {
                    let dir = cfg.auth_dir.clone();
                    let lock = Arc::clone(&ctx.creds_lock);
                    let dbg = Arc::clone(&ctx.debug);
                    tokio::spawn(async move {
                        if let Err(err) = save_creds_atomic(&dir, &creds, &lock).await {
                            dbg.record_error("creds_save", format!("{}", err)).await;
                        }
                    });
                }
                Ok(SocketEvent::Node(node)) => {
                    if registered && !activated.load(Ordering::SeqCst) {
                        let msg_ref = Arc::clone(&messages);
                        let ctx_ref = Arc::clone(&ctx);
                        let act_ref = Arc::clone(&activated);
                        let dir_ref = cfg.auth_dir.clone();
                        tokio::spawn(async move {
                            activate_session(&msg_ref, &ctx_ref, &act_ref, &dir_ref, connect_started).await;
                        });
                    }
                    let r = Arc::clone(&recv);
                    let dbg = Arc::clone(&ctx.debug);
                    tokio::spawn(async move {
                        if let Err(err) = r.process_node(&node).await {
                            dbg.log("node_err", format!("{}", err));
                        }
                    });
                }
                Err(RecvError::Lagged(skipped)) => {
                    ctx.debug.socket_lagged.fetch_add(skipped, Ordering::Relaxed);
                    ctx.debug
                        .record_error("socket_rx", format!("lagged {} eventos", skipped))
                        .await;
                }
                Err(RecvError::Closed) => {
                    reconnect = true;
                    break;
                }
            }
        }

        recv_task.abort();
        if !reconnect {
            break;
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(5_000);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_aura_config();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .max_blocking_threads(64)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?;

    runtime.block_on(run_aura(cfg))
}
