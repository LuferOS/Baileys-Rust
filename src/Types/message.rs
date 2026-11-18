use crate::proto::Message;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Chat,
    PeerBroadcast,
    OtherBroadcast,
    Group,
    DirectPeerStatus,
    OtherStatus,
    Newsletter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressingContext {
    pub addressing_mode: String,
    pub sender_alt: Option<String>,
    pub recipient_alt: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaMessageKey {
    pub remote_jid: Option<String>,
    pub remote_jid_alt: Option<String>,
    pub remote_jid_username: Option<String>,
    pub from_me: Option<bool>,
    pub id: Option<String>,
    pub participant: Option<String>,
    pub participant_alt: Option<String>,
    pub participant_username: Option<String>,
    pub addressing_mode: Option<String>,
    pub server_id: Option<String>,
    pub is_view_once: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WaMessage {
    pub key: WaMessageKey,
    pub category: Option<String>,
    pub message_timestamp: Option<u64>,
    pub push_name: Option<String>,
    pub broadcast: Option<bool>,
    pub status: Option<i32>,
    pub verified_biz_name: Option<String>,
    pub retry_count: Option<u32>,
    pub message: Option<Message>,
    pub message_stub_type: Option<i32>,
    pub message_stub_parameters: Vec<String>,
}
