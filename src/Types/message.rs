use crate::proto::{Message, MessageKey, PollUpdate, Reaction, UserReceipt};
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

impl WaMessageKey {
    pub fn to_proto(&self) -> MessageKey {
        MessageKey {
            remote_jid: self.remote_jid.clone(),
            from_me: self.from_me,
            id: self.id.clone(),
            participant: self.participant.clone(),
        }
    }

    pub fn from_proto(key: &MessageKey) -> Self {
        Self {
            remote_jid: key.remote_jid.clone(),
            from_me: key.from_me,
            id: key.id.clone(),
            participant: key.participant.clone(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WaMessage {
    pub key: WaMessageKey,
    pub category: Option<String>,
    pub message_timestamp: Option<u64>,
    pub push_name: Option<String>,
    pub broadcast: Option<bool>,
    pub status: Option<i32>,
    pub participant: Option<String>,
    pub verified_biz_name: Option<String>,
    pub retry_count: Option<u32>,
    pub message: Option<Message>,
    pub message_stub_type: Option<i32>,
    pub message_stub_parameters: Vec<String>,
    pub user_receipt: Vec<UserReceipt>,
    pub reactions: Vec<Reaction>,
    pub poll_updates: Vec<PollUpdate>,
}
