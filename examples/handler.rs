use baileys_rs::proto::message::{ExtendedTextMessage, ImageMessage};
use baileys_rs::proto::Message;
use baileys_rs::socket::MessagesSocket;
use baileys_rs::types::WaMessage;
use baileys_rs::utils::normalize_message_content;
use std::borrow::Borrow;
use std::sync::Arc;

use crate::{cmd, BotContext};

pub fn extract_message_text(msg: &Message) -> Option<String> {
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
    if let Some(ref img) = norm.image_message {
        let inner: &ImageMessage = Borrow::borrow(img);
        if let Some(ref cap) = inner.caption {
            if !cap.is_empty() {
                return Some(cap.clone());
            }
        }
    }
    None
}

pub fn parse_command(raw_text: &str, prefixes: &[String]) -> Option<(String, String)> {
    let trimmed = raw_text.trim();
    for p in prefixes {
        if let Some(rest) = trimmed.strip_prefix(p.as_str()) {
            let rest_trimmed = rest.trim_start();
            if rest_trimmed.is_empty() {
                return None;
            }
            let mut parts = rest_trimmed.splitn(2, char::is_whitespace);
            let cmd = parts.next().unwrap_or("").to_ascii_lowercase();
            let args = parts.next().unwrap_or("").trim().to_string();
            return Some((cmd, args));
        }
    }
    None
}

pub async fn dispatch(
    messages: &Arc<MessagesSocket>,
    ctx: &BotContext,
    message: WaMessage,
    cmd_name: &str,
    args: &str,
) {
    let creds = messages.socket.creds().await;
    let me_jid = creds.me.as_ref().map(|m| m.id.clone());

    if cmd::system::run(messages, ctx, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::sticker::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::group::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::download::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::utils::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::ai::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::economy::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::gacha::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::games::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::funy::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::interaccion::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::profile::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::search::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::socket::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    if cmd::stalk::run(messages, message.clone(), cmd_name, args, me_jid.clone()).await {
        return;
    }
    let _ = cmd::nsfw::run(messages, message, cmd_name, args, me_jid).await;
}
