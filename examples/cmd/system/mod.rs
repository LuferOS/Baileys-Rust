use baileys_rs::proto::Message;
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
    let _ = messages
        .send_message(
            remote_jid,
            AnyMessageContent::Raw(Message {
                conversation: Some(text),
                ..Default::default()
            }),
            opts,
        )
        .await;
}

pub async fn run(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    message: WaMessage,
    cmd: &str,
    _args: &str,
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
            let ping_str = ping
                .map(|ms| format!("{:.2} ms (IQ w:p)", ms))
                .unwrap_or_else(|| "N/A".to_string());
            let modules = ACTIVE_MODULES
                .iter()
                .map(|m| format!("  - {}", m))
                .collect::<Vec<_>>()
                .join("\n");

            let body = format!(
                "*{}* (`baileys-rs` v{})\n\
                Estado: Operativo\n\
                Cuenta: {}\n\n\
                *Rendimiento*\n\
                - Ping WhatsApp: {}\n\
                - Proceso local: {:.3} ms\n\
                - Uptime: {}\n\
                - Mensajes procesados: {}\n\n\
                *Memoria y Runtime*\n\
                - RAM actual (VmRSS): {:.2} MB\n\
                - RAM pico (VmHWM): {:.2} MB\n\
                - Workers Tokio: {} | Hilos totales: {}\n\
                - Rust: {}\n\
                - Sistema: {}/{}\n\
                - WA Web: {}.{}.{}\n\n\
                *Modulos activos ({})*\n\
                {}",
                BOT_NAME,
                env!("CARGO_PKG_VERSION"),
                me_jid.as_deref().unwrap_or("desconocida"),
                ping_str,
                local_ms,
                format_uptime(ctx.started_at.elapsed()),
                total_msgs,
                stats.rss_mb,
                stats.hwm_mb,
                ctx.worker_threads,
                stats.threads,
                env!("BAILEYS_RUSTC_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                ctx.wa_version[0],
                ctx.wa_version[1],
                ctx.wa_version[2],
                ACTIVE_MODULES.len(),
                modules
            );
            send_reply(messages, &remote_jid, message, me_jid, body).await;
            true
        }
        "ping" => {
            let ping = measure_wa_ping_ms(messages).await;
            let local_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let ping_txt = ping
                .map(|ms| format!("{:.2} ms", ms))
                .unwrap_or_else(|| "N/A".to_string());
            let body = format!(
                "*{} — Pong*\nPing WA: {}\nProceso local: {:.3} ms",
                BOT_NAME, ping_txt, local_ms
            );
            send_reply(messages, &remote_jid, message, me_jid, body).await;
            true
        }
        "ram" => {
            let stats = read_process_stats();
            let body = format!(
                "*{} — Memoria*\nRSS: {:.2} MB\nPico (HWM): {:.2} MB\nWorkers: {} | Hilos: {}",
                BOT_NAME, stats.rss_mb, stats.hwm_mb, ctx.worker_threads, stats.threads
            );
            send_reply(messages, &remote_jid, message, me_jid, body).await;
            true
        }
        "help" | "menu" => {
            let p = ctx.prefixes.first().map(String::as_str).unwrap_or(".");
            let body = format!(
                "*{} — Comandos*\n\
                Prefijos: {}\n\n\
                [system]\n\
                - `{}info` / `{}aura`\n\
                - `{}ping`\n\
                - `{}ram`\n\
                - `{}help`\n\n\
                [sticker]\n\
                - `{}s` / `{}sticker`",
                BOT_NAME,
                ctx.prefixes.join("  "),
                p,
                p,
                p,
                p,
                p,
                p,
                p
            );
            send_reply(messages, &remote_jid, message, me_jid, body).await;
            true
        }
        _ => false,
    }
}
