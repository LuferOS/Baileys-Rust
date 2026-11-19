use crate::proto::sync_action_value::{
    ContactAction, PrivacySettingDisableLinkPreviewsAction, PrivacySettingRelayAllCalls,
    StatusPrivacyAction, SyncActionMessage, SyncActionMessageRange, TimeFormatAction,
};
use crate::proto::{SyncActionData, SyncActionValue};
use crate::types::{LidMapping, WaMessageKey, WaPatchName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtHashValueMac {
    pub value_mac: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtHashState {
    pub version: u64,
    pub hash: Vec<u8>,
    pub index_value_map: HashMap<String, LtHashValueMac>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatMutation {
    pub sync_action: SyncActionData,
    pub index: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WaPatchCreate {
    pub sync_action: SyncActionValue,
    pub index: Vec<String>,
    pub patch_type: WaPatchName,
    pub api_version: i32,
    pub operation: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelAssociationType {
    Chat,
    Message,
}

impl LabelAssociationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LabelAssociationType::Chat => "label_jid",
            LabelAssociationType::Message => "label_message",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelActionBody {
    pub id: String,
    pub name: String,
    pub color: i32,
    pub predefined_id: Option<i32>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelAssociation {
    Chat {
        chat_id: String,
        label_id: String,
    },
    Message {
        chat_id: String,
        message_id: String,
        label_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickReplyInput {
    pub timestamp: Option<String>,
    pub shortcut: Option<String>,
    pub message: Option<String>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarMessageTarget {
    pub id: String,
    pub from_me: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LastMessageList {
    Messages(Vec<SyncActionMessage>),
    Range(SyncActionMessageRange),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChatModification {
    Mute(Option<i64>),
    Archive {
        archive: bool,
        last_messages: LastMessageList,
    },
    MarkRead {
        mark_read: bool,
        last_messages: LastMessageList,
    },
    DeleteForMe {
        key: WaMessageKey,
        timestamp: i64,
        delete_media: bool,
    },
    Clear {
        last_messages: LastMessageList,
    },
    Pin(bool),
    Contact(Option<ContactAction>),
    DisableLinkPreviews(bool),
    Star {
        messages: Vec<StarMessageTarget>,
        star: bool,
    },
    Delete {
        last_messages: LastMessageList,
    },
    PushNameSetting(String),
    QuickReply(QuickReplyInput),
    AddLabel(LabelActionBody),
    AddChatLabel {
        label_id: String,
    },
    RemoveChatLabel {
        label_id: String,
    },
    AddMessageLabel {
        message_id: String,
        label_id: String,
    },
    RemoveMessageLabel {
        message_id: String,
        label_id: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncContact {
    pub id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub lid: Option<String>,
    pub phone_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncActionEvent {
    ContactsUpsert(Vec<SyncContact>),
    LidMappingUpdate(LidMapping),
    ChatMuteUpdate {
        id: String,
        mute_end_time: Option<i64>,
    },
    ChatArchiveUpdate {
        id: String,
        archived: bool,
        message_range: Option<SyncActionMessageRange>,
    },
    ChatReadUpdate {
        id: String,
        unread_count: Option<i32>,
        message_range: Option<SyncActionMessageRange>,
    },
    ChatPinUpdate {
        id: String,
        pinned: Option<i64>,
    },
    ChatDelete(Vec<String>),
    ChatLock {
        id: String,
        locked: bool,
    },
    MessagesDelete(Vec<WaMessageKey>),
    MessageStarUpdate {
        key: WaMessageKey,
        starred: bool,
    },
    CredsPushNameUpdate(String),
    CredsUnarchiveChatsUpdate(bool),
    LabelEdit {
        id: String,
        name: String,
        color: i32,
        deleted: bool,
        predefined_id: Option<String>,
    },
    LabelAssociation {
        added: bool,
        association: LabelAssociation,
    },
    SettingLocale(String),
    SettingTimeFormat(TimeFormatAction),
    SettingRelayAllCalls(PrivacySettingRelayAllCalls),
    SettingStatusPrivacy(StatusPrivacyAction),
    SettingDisableLinkPreviews(PrivacySettingDisableLinkPreviewsAction),
    SettingNotificationActivity(i32),
    SettingChannelsPersonalisedRecommendation(bool),
}
