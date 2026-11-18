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
