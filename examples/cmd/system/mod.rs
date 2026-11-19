use baileys_rs::socket::MessagesSocket;
use baileys_rs::types::WaMessage;
use baileys_rs::utils::{AnyMessageContent, MessageGenerationOptions};
use baileys_rs::wa_binary::{BinaryNode, BinaryNodeAttributes, BinaryNodeData, S_WHATSAPP_NET};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{BotContext, BOT_NAME};

struct ProcessStats {
    rss_mb: f64,
    hwm_mb: f64,
    threads: u32,
}

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
    format!(
        "{:02}h {:02}m {:02}s",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

async fn measure_wa_ping_ms(messages: &Arc<MessagesSocket>) -> Option<f64> {
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
    messages
        .socket
        .query(ping_iq, Some(2_500))
        .await
        .ok()
        .map(|_| start.elapsed().as_secs_f64() * 1000.0)
}

async fn send_reply(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    remote_jid: &str,
    quoted: WaMessage,
    user_jid: Option<String>,
    text: String,
) {
    let opts = MessageGenerationOptions {
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
    };
    if let Err(err) = messages
        .send_message(remote_jid, AnyMessageContent::Text(text), opts)
        .await
    {
        ctx.debug
            .record_error("send_reply", format!("{}: {}", remote_jid, err))
            .await;
    }
}

pub async fn run(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    message: WaMessage,
    cmd: &str,
    args: &str,
    me_jid: Option<String>,
) -> bool {
    let Some(remote_jid) = message.key.remote_jid.clone() else {
        return false;
    };
    let t0 = Instant::now();
    let total_msgs = ctx.processed_msgs.load(Ordering::Relaxed);

    match cmd {
        "info" | "aura" => {
            let ping = measure_wa_ping_ms(messages).await;
            let local_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let stats = read_process_stats();
            let snap = ctx.debug.snapshot().await;
            let ping_str = ping
                .map(|ms| format!("{:.2} ms (IQ w:p)", ms))
                .unwrap_or_else(|| "N/A".to_string());
            let modules = ACTIVE_MODULES
                .iter()
                .map(|m| format!("  - {}", m))
                .collect::<Vec<_>>()
                .join("\n");

            let body = format!(
                "*{bot}* (`baileys-rs` v{ver})\n\
                Estado: Operativo | Debug: {dbg}\n\
                Cuenta: {acc}\n\n\
                *Rendimiento*\n\
                - Ping WhatsApp: {ping}\n\
                - Proceso local: {local:.3} ms\n\
                - Uptime: {up}\n\
                - Mensajes: {msgs} | Comandos: {cmds} | Activos: {act}\n\n\
                *Memoria y Runtime*\n\
                - RAM actual (VmRSS): {rss:.2} MB\n\
                - RAM pico (VmHWM): {hwm:.2} MB\n\
                - Workers Tokio: {wrk} | Hilos: {thr}\n\
                - Lag socket/recv: {slag}/{rlag} | Errores: {errs}\n\
                - Rust: {rustc}\n\
                - Sistema: {os}/{arch}\n\
                - WA Web: {w0}.{w1}.{w2}\n\n\
                *Modulos activos ({mcnt})*\n\
                {mods}",
                bot = BOT_NAME,
                ver = env!("CARGO_PKG_VERSION"),
                dbg = if snap.enabled { "ON" } else { "OFF" },
                acc = me_jid.as_deref().unwrap_or("desconocida"),
                ping = ping_str,
                local = local_ms,
                up = format_uptime(ctx.started_at.elapsed()),
                msgs = total_msgs,
                cmds = snap.total_commands,
                act = snap.active_tasks,
                rss = stats.rss_mb,
                hwm = stats.hwm_mb,
                wrk = ctx.worker_threads,
                thr = stats.threads,
                slag = snap.socket_lagged,
                rlag = snap.recv_lagged,
                errs = snap.total_errors,
                rustc = env!("BAILEYS_RUSTC_VERSION"),
                os = std::env::consts::OS,
                arch = std::env::consts::ARCH,
                w0 = ctx.wa_version[0],
                w1 = ctx.wa_version[1],
                w2 = ctx.wa_version[2],
                mcnt = ACTIVE_MODULES.len(),
                mods = modules
            );
            send_reply(messages, ctx, &remote_jid, message, me_jid, body).await;
            true
        }
        "ping" => {
            let ping = measure_wa_ping_ms(messages).await;
            let local_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let ping_txt = ping
                .map(|ms| format!("{:.2} ms", ms))
                .unwrap_or_else(|| "N/A".to_string());
            let body = format!(
                "*{bot} — Pong*\nPing WA: {ping}\nProceso local: {local:.3} ms",
                bot = BOT_NAME,
                ping = ping_txt,
                local = local_ms
            );
            send_reply(messages, ctx, &remote_jid, message, me_jid, body).await;
            true
        }
        "ram" => {
            let stats = read_process_stats();
            let snap = ctx.debug.snapshot().await;
            let body = format!(
                "*{bot} — Memoria*\nRSS: {rss:.2} MB\nPico (HWM): {hwm:.2} MB\nWorkers: {wrk} | Hilos: {thr}\nTareas activas: {act}",
                bot = BOT_NAME,
                rss = stats.rss_mb,
                hwm = stats.hwm_mb,
                wrk = ctx.worker_threads,
                thr = stats.threads,
                act = snap.active_tasks
            );
            send_reply(messages, ctx, &remote_jid, message, me_jid, body).await;
            true
        }
        "debug" => {
            let sub = args.trim().to_ascii_lowercase();
            match sub.as_str() {
                "on" => {
                    ctx.debug.set_enabled(true);
                    send_reply(
                        messages,
                        ctx,
                        &remote_jid,
                        message,
                        me_jid,
                        "Debug en consola: *ACTIVADO*".to_string(),
                    )
                    .await;
                }
                "off" => {
                    ctx.debug.set_enabled(false);
                    send_reply(
                        messages,
                        ctx,
                        &remote_jid,
                        message,
                        me_jid,
                        "Debug en consola: *DESACTIVADO*".to_string(),
                    )
                    .await;
                }
                "clear" => {
                    ctx.debug.clear().await;
                    send_reply(
                        messages,
                        ctx,
                        &remote_jid,
                        message,
                        me_jid,
                        "Contadores e historial de debug reiniciados.".to_string(),
                    )
                    .await;
                }
                _ => {
                    let snap = ctx.debug.snapshot().await;
                    let errs_txt = if snap.last_errors.is_empty() {
                        "  (sin errores)".to_string()
                    } else {
                        snap.last_errors
                            .iter()
                            .rev()
                            .take(6)
                            .map(|e| format!("  - {e}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    let perf_txt = if snap.last_timings.is_empty() {
                        "  (sin registros)".to_string()
                    } else {
                        snap.last_timings
                            .iter()
                            .rev()
                            .take(6)
                            .map(|t| format!("  - {t}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    let body = format!(
                        "*{bot} — Debug*\n\
                        Consola: {state}\n\
                        Socket lag: {slag} | Recv lag: {rlag}\n\
                        Tareas activas: {act} | Comandos: {cmds} | Errores: {errs}\n\n\
                        *Ultimos tiempos*\n\
                        {perf}\n\n\
                        *Ultimos errores*\n\
                        {err_list}\n\n\
                        Uso: `.debug on | off | clear`",
                        bot = BOT_NAME,
                        state = if snap.enabled { "ON" } else { "OFF" },
                        slag = snap.socket_lagged,
                        rlag = snap.recv_lagged,
                        act = snap.active_tasks,
                        cmds = snap.total_commands,
                        errs = snap.total_errors,
                        perf = perf_txt,
                        err_list = errs_txt
                    );
                    send_reply(messages, ctx, &remote_jid, message, me_jid, body).await;
                }
            }
            true
        }
        "help" | "menu" => {
            let p = ctx.prefixes.first().map(String::as_str).unwrap_or(".");
            let body = format!(
                "*{bot} — Comandos*\n\
                Prefijos: {prefs}\n\n\
                [system]\n\
                - `{p}info` / `{p}aura`\n\
                - `{p}ping`\n\
                - `{p}ram`\n\
                - `{p}debug [on|off|clear]`\n\
                - `{p}help`\n\n\
                [sticker]\n\
                - `{p}s` / `{p}sticker`",
                bot = BOT_NAME,
                prefs = ctx.prefixes.join("  "),
                p = p
            );
            send_reply(messages, ctx, &remote_jid, message, me_jid, body).await;
            true
        }
        _ => false,
    }
}
