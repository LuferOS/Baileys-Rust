use crate::proto::AdvSignedDeviceIdentity;
use crate::utils::crypto::{signed_key_pair, CryptoError, Curve};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::{rngs::OsRng, RngCore};
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccountSettings {
    pub unarchive_chats: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PairingCredsUpdate {
    pub account: AdvSignedDeviceIdentity,
    pub me: ContactInfo,
    pub signal_identities: Vec<SignalIdentity>,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationCreds {
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key_pair: KeyPair,
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u32,
    pub adv_secret_key: String,
    pub processed_history_messages: Vec<serde_json::Value>,
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
    pub account_sync_counter: u32,
    pub account_settings: AccountSettings,
    pub registered: bool,
    pub pairing_code: Option<String>,
    pub last_prop_hash: Option<String>,
    pub routing_info: Option<Vec<u8>>,
    pub me: Option<ContactInfo>,
    pub account: Option<Vec<u8>>,
    pub signal_identities: Vec<SignalIdentity>,
    pub my_app_state_key_id: Option<String>,
    pub platform: Option<String>,
}

impl AuthenticationCreds {
    pub fn signal_creds(&self) -> SignalCreds {
        SignalCreds {
            signed_identity_key: self.signed_identity_key.clone(),
            signed_pre_key: self.signed_pre_key.clone(),
            registration_id: self.registration_id,
        }
    }
}

pub fn generate_registration_id() -> u32 {
    let mut bytes = [0u8; 2];
    OsRng.fill_bytes(&mut bytes);
    u32::from(u16::from_le_bytes(bytes) & 16383)
}

pub fn init_auth_creds() -> Result<AuthenticationCreds, CryptoError> {
    let identity_key = Curve::generate_key_pair();
    let signed_pre_key = signed_key_pair(&identity_key, 1)?;
    let mut adv_secret = [0u8; 32];
    OsRng.fill_bytes(&mut adv_secret);

    Ok(AuthenticationCreds {
        noise_key: Curve::generate_key_pair(),
        pairing_ephemeral_key_pair: Curve::generate_key_pair(),
        signed_identity_key: identity_key,
        signed_pre_key,
        registration_id: generate_registration_id(),
        adv_secret_key: BASE64.encode(adv_secret),
        processed_history_messages: Vec::new(),
        next_pre_key_id: 1,
        first_unuploaded_pre_key_id: 1,
        account_sync_counter: 0,
        account_settings: AccountSettings {
            unarchive_chats: false,
        },
        registered: false,
        pairing_code: None,
        last_prop_hash: None,
        routing_info: None,
        me: None,
        account: None,
        signal_identities: Vec::new(),
        my_app_state_key_id: None,
        platform: None,
    })
}
