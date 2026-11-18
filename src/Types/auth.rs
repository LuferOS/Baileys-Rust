use crate::proto::AdvSignedDeviceIdentity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub key_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolAddress {
    pub name: String,
    pub device_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalIdentity {
    pub identifier: ProtocolAddress,
    pub identifier_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalCreds {
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactInfo {
    pub id: String,
    pub name: Option<String>,
    pub lid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PairingCredsUpdate {
    pub account: AdvSignedDeviceIdentity,
    pub me: ContactInfo,
    pub signal_identities: Vec<SignalIdentity>,
    pub platform: Option<String>,
}
