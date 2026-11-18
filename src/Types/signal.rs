use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2ESessionPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2ESessionSignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2ESession {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: E2ESessionSignedPreKey,
    pub pre_key: Option<E2ESessionPreKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListData {
    pub id: u32,
    pub key_index: Option<u32>,
    pub is_hosted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedDeviceInfo {
    pub device_list: Vec<DeviceListData>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct USyncDeviceEntry {
    pub id: String,
    pub devices: Option<ParsedDeviceInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeysCredsUpdate {
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LidMapping {
    pub pn: String,
    pub lid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCipherType {
    Pkmsg,
    Msg,
}

impl MessageCipherType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageCipherType::Pkmsg => "pkmsg",
            MessageCipherType::Msg => "msg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub cipher_type: MessageCipherType,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedGroupMessage {
    pub ciphertext: Vec<u8>,
    pub sender_key_distribution_message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub base_key: Vec<u8>,
    pub registration_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionValidation {
    pub exists: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateSessionResult {
    pub migrated: usize,
    pub skipped: usize,
    pub total: usize,
}
