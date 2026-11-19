use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    Connecting,
    AwaitingInitialSync,
    Syncing,
    Online,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProps {
    pub privacy_token_on_1to1: bool,
    pub profile_pic_privacy_token: bool,
    pub lid_trusted_token_issue_to_lid: bool,
}

impl Default for ServerProps {
    fn default() -> Self {
        Self {
            privacy_token_on_1to1: true,
            profile_pic_privacy_token: true,
            lid_trusted_token_issue_to_lid: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WaPatchName {
    CriticalBlock,
    CriticalUnblockLow,
    RegularHigh,
    RegularLow,
    Regular,
}

impl WaPatchName {
    pub const ALL: [WaPatchName; 5] = [
        WaPatchName::CriticalBlock,
        WaPatchName::CriticalUnblockLow,
        WaPatchName::RegularHigh,
        WaPatchName::RegularLow,
        WaPatchName::Regular,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            WaPatchName::CriticalBlock => "critical_block",
            WaPatchName::CriticalUnblockLow => "critical_unblock_low",
            WaPatchName::RegularHigh => "regular_high",
            WaPatchName::RegularLow => "regular_low",
            WaPatchName::Regular => "regular",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotListInfo {
    pub jid: String,
    pub persona_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaPresence {
    Unavailable,
    Available,
    Composing,
    Recording,
    Paused,
}

impl WaPresence {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPresence::Unavailable => "unavailable",
            WaPresence::Available => "available",
            WaPresence::Composing => "composing",
            WaPresence::Recording => "recording",
            WaPresence::Paused => "paused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceData {
    pub last_known_presence: WaPresence,
    pub last_seen: Option<u64>,
    pub group_online_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceUpdate {
    pub id: String,
    pub presences: HashMap<String, PresenceData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaPrivacyValue {
    All,
    Contacts,
    ContactBlacklist,
    None,
}

impl WaPrivacyValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPrivacyValue::All => "all",
            WaPrivacyValue::Contacts => "contacts",
            WaPrivacyValue::ContactBlacklist => "contact_blacklist",
            WaPrivacyValue::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaPrivacyOnlineValue {
    All,
    MatchLastSeen,
}

impl WaPrivacyOnlineValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPrivacyOnlineValue::All => "all",
            WaPrivacyOnlineValue::MatchLastSeen => "match_last_seen",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaPrivacyCallValue {
    All,
    Known,
}

impl WaPrivacyCallValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPrivacyCallValue::All => "all",
            WaPrivacyCallValue::Known => "known",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaPrivacyMessagesValue {
    All,
    Contacts,
}

impl WaPrivacyMessagesValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPrivacyMessagesValue::All => "all",
            WaPrivacyMessagesValue::Contacts => "contacts",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaPrivacyGroupAddValue {
    All,
    Contacts,
    ContactBlacklist,
}

impl WaPrivacyGroupAddValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaPrivacyGroupAddValue::All => "all",
            WaPrivacyGroupAddValue::Contacts => "contacts",
            WaPrivacyGroupAddValue::ContactBlacklist => "contact_blacklist",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaReadReceiptsValue {
    All,
    None,
}

impl WaReadReceiptsValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaReadReceiptsValue::All => "all",
            WaReadReceiptsValue::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAction {
    Block,
    Unblock,
}

impl BlockAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockAction::Block => "block",
            BlockAction::Unblock => "unblock",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePictureType {
    Preview,
    Image,
}

impl ProfilePictureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfilePictureType::Preview => "preview",
            ProfilePictureType::Image => "image",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallLinkMedia {
    Audio,
    Video,
}

impl CallLinkMedia {
    pub fn as_str(&self) -> &'static str {
        match self {
            CallLinkMedia::Audio => "audio",
            CallLinkMedia::Video => "video",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyBitsType {
    AccountSync,
    Groups,
}

impl DirtyBitsType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DirtyBitsType::AccountSync => "account_sync",
            DirtyBitsType::Groups => "groups",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaBusinessHoursConfig {
    pub day_of_week: String,
    pub mode: String,
    pub open_time: Option<String>,
    pub close_time: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaBusinessHoursInfo {
    pub timezone: Option<String>,
    pub business_config: Vec<WaBusinessHoursConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaBusinessProfile {
    pub wid: Option<String>,
    pub address: Option<String>,
    pub description: String,
    pub website: Vec<String>,
    pub email: Option<String>,
    pub category: Option<String>,
    pub business_hours: WaBusinessHoursInfo,
}
