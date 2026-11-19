use serde::{Deserialize, Serialize};

pub struct XwaPaths;

impl XwaPaths {
    pub const XWA2_NEWSLETTER_CREATE: &'static str = "xwa2_newsletter_create";
    pub const XWA2_NEWSLETTER_SUBSCRIBERS: &'static str = "xwa2_newsletter_subscribers";
    pub const XWA2_NEWSLETTER_VIEW: &'static str = "xwa2_newsletter_view";
    pub const XWA2_NEWSLETTER_METADATA: &'static str = "xwa2_newsletter";
    pub const XWA2_NEWSLETTER_ADMIN_COUNT: &'static str = "xwa2_newsletter_admin";
    pub const XWA2_NEWSLETTER_MUTE_V2: &'static str = "xwa2_newsletter_mute_v2";
    pub const XWA2_NEWSLETTER_UNMUTE_V2: &'static str = "xwa2_newsletter_unmute_v2";
    pub const XWA2_NEWSLETTER_FOLLOW: &'static str = "xwa2_newsletter_follow";
    pub const XWA2_NEWSLETTER_UNFOLLOW: &'static str = "xwa2_newsletter_unfollow";
    pub const XWA2_NEWSLETTER_JOIN_V2: &'static str = "xwa2_newsletter_join_v2";
    pub const XWA2_NEWSLETTER_LEAVE_V2: &'static str = "xwa2_newsletter_leave_v2";
    pub const XWA2_NEWSLETTER_CHANGE_OWNER: &'static str = "xwa2_newsletter_change_owner";
    pub const XWA2_NEWSLETTER_DEMOTE: &'static str = "xwa2_newsletter_demote";
    pub const XWA2_NEWSLETTER_DELETE_V2: &'static str = "xwa2_newsletter_delete_v2";
    pub const XWA2_FETCH_ACCOUNT_REACHOUT_TIMELOCK: &'static str =
        "xwa2_fetch_account_reachout_timelock";
    pub const XWA2_MESSAGE_CAPPING_INFO: &'static str = "xwa2_message_capping_info";
}

pub struct QueryIds;

impl QueryIds {
    pub const CREATE: &'static str = "8823471724422422";
    pub const UPDATE_METADATA: &'static str = "24250201037901610";
    pub const METADATA: &'static str = "6563316087068696";
    pub const SUBSCRIBERS: &'static str = "9783111038412085";
    pub const FOLLOW: &'static str = "24404358912487870";
    pub const UNFOLLOW: &'static str = "9767147403369991";
    pub const MUTE: &'static str = "29766401636284406";
    pub const UNMUTE: &'static str = "9864994326891137";
    pub const ADMIN_COUNT: &'static str = "7130823597031706";
    pub const CHANGE_OWNER: &'static str = "7341777602580933";
    pub const DEMOTE: &'static str = "6551828931592903";
    pub const DELETE: &'static str = "30062808666639665";
    pub const REACHOUT_TIMELOCK: &'static str = "23983697327930364";
    pub const MESSAGE_CAPPING_INFO: &'static str = "24503548349331633";
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NewsletterViewRole {
    #[serde(rename = "ADMIN")]
    Admin,
    #[serde(rename = "GUEST")]
    Guest,
    #[serde(rename = "OWNER")]
    Owner,
    #[serde(rename = "SUBSCRIBER")]
    Subscriber,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterState {
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterTextField {
    pub id: String,
    pub text: String,
    pub update_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterRawPicture {
    pub direct_path: String,
    pub id: String,
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterCreateThreadMetadata {
    pub creation_time: String,
    pub description: NewsletterTextField,
    pub handle: Option<String>,
    pub invite: String,
    pub name: NewsletterTextField,
    pub picture: NewsletterRawPicture,
    pub preview: NewsletterRawPicture,
    pub subscribers_count: String,
    pub verification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterCreateViewerMetadata {
    pub mute: String,
    pub role: NewsletterViewRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterCreateResponse {
    pub id: String,
    pub state: NewsletterState,
    pub thread_metadata: NewsletterCreateThreadMetadata,
    pub viewer_metadata: NewsletterCreateViewerMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterPicture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "directPath", skip_serializing_if = "Option::is_none")]
    pub direct_path: Option<String>,
    #[serde(rename = "mediaKey", skip_serializing_if = "Option::is_none")]
    pub media_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterReactionCode {
    pub code: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterThreadSummary {
    pub creation_time: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewsletterMetadata {
    pub id: String,
    pub owner: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub invite: Option<String>,
    pub creation_time: Option<u64>,
    pub subscribers: Option<u64>,
    pub picture: Option<NewsletterPicture>,
    pub verification: Option<String>,
    pub reaction_codes: Option<Vec<NewsletterReactionCode>>,
    pub mute_state: Option<String>,
    pub thread_metadata: Option<NewsletterThreadSummary>,
}
