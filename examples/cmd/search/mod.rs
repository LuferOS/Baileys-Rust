use baileys_rs::socket::MessagesSocket;
use baileys_rs::types::WaMessage;
use std::sync::Arc;

pub async fn run(
    _messages: &Arc<MessagesSocket>,
    _message: WaMessage,
    _cmd: &str,
    _args: &str,
    _me_jid: Option<String>,
) -> bool {
    false
}
