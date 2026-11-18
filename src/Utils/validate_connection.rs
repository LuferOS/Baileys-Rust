use crate::defaults::{
    KEY_BUNDLE_TYPE, WA_ADV_ACCOUNT_SIG_PREFIX, WA_ADV_DEVICE_SIG_PREFIX,
    WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX,
};
use crate::proto::{
    client_payload, device_props, AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity,
    AdvSignedDeviceIdentityHmac, ClientPayload, DeviceProps,
};
use crate::types::{
    ContactInfo, KeyPair, PairingCredsUpdate, ProtocolAddress, SignalCreds, SignalIdentity,
    SocketConfig,
};
use crate::utils::crypto::{
    generate_signal_pub_key, hmac_sign, md5, CryptoError, Curve, HmacVariant,
};
use crate::wa_binary::{
    get_binary_node_child, jid_decode, BinaryNode, BinaryNodeAttributes, BinaryNodeData,
    S_WHATSAPP_NET,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prost::Message;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidateConnectionError {
    #[error("invalid jid: {0}")]
    InvalidJid(String),
    #[error("invalid username in jid: {0}")]
    InvalidUsername(String),
    #[error("missing device-identity or device in pair success node")]
    MissingPairSuccessNodes,
    #[error("missing required attribute: {0}")]
    MissingAttribute(&'static str),
    #[error("invalid base64 adv secret key: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid account hmac signature")]
    InvalidAccountHmac,
    #[error("failed to verify account signature")]
    InvalidAccountSignature,
    #[error("missing binary payload in device-identity")]
    MissingDeviceIdentityBytes,
}

pub struct PairingResult {
    pub creds: PairingCredsUpdate,
    pub reply: BinaryNode,
}

pub fn encode_big_endian(value: u32, len: usize) -> Vec<u8> {
    let mut r = value;
    let mut out = vec![0u8; len];
    for i in (0..len).rev() {
        out[i] = (r & 0xff) as u8;
        r >>= 8;
    }
    out
}

fn create_signal_identity(wid: &str, account_signature_key: &[u8]) -> SignalIdentity {
    SignalIdentity {
        identifier: ProtocolAddress {
            name: wid.to_string(),
            device_id: 0,
        },
        identifier_key: generate_signal_pub_key(account_signature_key),
    }
}

fn get_user_agent(config: &SocketConfig) -> client_payload::UserAgent {
    let platform = if config.browser[1].to_lowercase().contains("android") {
        client_payload::user_agent::Platform::Android as i32
    } else {
        client_payload::user_agent::Platform::Web as i32
    };

    client_payload::UserAgent {
        app_version: Some(client_payload::user_agent::AppVersion {
            primary: Some(config.version[0]),
            secondary: Some(config.version[1]),
            tertiary: Some(config.version[2]),
            ..Default::default()
        }),
        platform: Some(platform),
        release_channel: Some(client_payload::user_agent::ReleaseChannel::Release as i32),
        os_version: Some("0.1".to_string()),
        device: Some("Desktop".to_string()),
        os_build_number: Some("0.1".to_string()),
        locale_language_iso6391: Some("en".to_string()),
        mnc: Some("000".to_string()),
        mcc: Some("000".to_string()),
        locale_country_iso31661_alpha2: Some(config.country_code.clone()),
        ..Default::default()
    }
}

fn get_web_info(config: &SocketConfig) -> client_payload::WebInfo {
    let mut web_sub_platform = client_payload::web_info::WebSubPlatform::WebBrowser as i32;
    if config.sync_full_history && config.browser[1] == "Desktop" {
        if config.browser[0] == "Mac OS" {
            web_sub_platform = client_payload::web_info::WebSubPlatform::Darwin as i32;
        } else if config.browser[0] == "Windows" {
            web_sub_platform = client_payload::web_info::WebSubPlatform::WinHybrid as i32;
        }
    }

    client_payload::WebInfo {
        web_sub_platform: Some(web_sub_platform),
        ..Default::default()
    }
}

fn get_client_payload(config: &SocketConfig) -> ClientPayload {
    let web_info = if !config.browser[1].to_lowercase().contains("android") {
        Some(get_web_info(config))
    } else {
        None
    };

    ClientPayload {
        connect_type: Some(client_payload::ConnectType::WifiUnknown as i32),
        connect_reason: Some(client_payload::ConnectReason::UserActivated as i32),
        user_agent: Some(get_user_agent(config)),
        web_info,
        push_name: config.push_name.clone(),
        ..Default::default()
    }
}

pub fn generate_login_node(
    user_jid: &str,
    config: &SocketConfig,
) -> Result<ClientPayload, ValidateConnectionError> {
    let decoded = jid_decode(user_jid)
        .ok_or_else(|| ValidateConnectionError::InvalidJid(user_jid.to_string()))?;
    let username = decoded
        .user
        .parse::<u64>()
        .map_err(|_| ValidateConnectionError::InvalidUsername(decoded.user.clone()))?;

    let mut payload = get_client_payload(config);
    payload.passive = Some(true);
    payload.pull = Some(true);
    payload.username = Some(username);
    payload.device = decoded.device;
    payload.lid_db_migrated = Some(false);
    Ok(payload)
}

fn get_platform_type(platform: &str) -> i32 {
    let upper = platform.to_uppercase();
    if upper == "ANDROID" {
        return device_props::PlatformType::AndroidPhone as i32;
    }
    device_props::PlatformType::from_str_name(&upper)
        .unwrap_or(device_props::PlatformType::Chrome) as i32
}

pub fn generate_registration_node(creds: &SignalCreds, config: &SocketConfig) -> ClientPayload {
    let version_str = format!(
        "{}.{}.{}",
        config.version[0], config.version[1], config.version[2]
    );
    let app_version_buf = md5(version_str.as_bytes());

    let companion = DeviceProps {
        os: Some(config.browser[0].clone()),
        platform_type: Some(get_platform_type(&config.browser[1])),
        require_full_sync: Some(config.sync_full_history),
        history_sync_config: Some(device_props::HistorySyncConfig {
            storage_quota_mb: Some(10240),
            inline_initial_payload_in_e2_ee_msg: Some(true),
            support_call_log_history: Some(false),
            support_bot_user_agent_chat_history: Some(true),
            support_cag_reactions_and_polls: Some(true),
            support_biz_hosted_msg: Some(true),
            support_recent_sync_chunk_message_count_tuning: Some(true),
            support_hosted_group_msg: Some(true),
            support_fbid_bot_chat_history: Some(true),
            support_message_association: Some(true),
            support_group_history: Some(false),
            ..Default::default()
        }),
        version: Some(device_props::AppVersion {
            primary: Some(10),
            secondary: Some(15),
            tertiary: Some(7),
            ..Default::default()
        }),
        ..Default::default()
    };

    let companion_proto = companion.encode_to_vec();

    let mut payload = get_client_payload(config);
    payload.passive = Some(false);
    payload.pull = Some(false);
    payload.device_pairing_data = Some(client_payload::DevicePairingRegistrationData {
        build_hash: Some(app_version_buf),
        device_props: Some(companion_proto),
        e_regid: Some(encode_big_endian(creds.registration_id, 4)),
        e_keytype: Some(KEY_BUNDLE_TYPE.to_vec()),
        e_ident: Some(creds.signed_identity_key.public.clone()),
        e_skey_id: Some(encode_big_endian(creds.signed_pre_key.key_id, 3)),
        e_skey_val: Some(creds.signed_pre_key.key_pair.public.clone()),
        e_skey_sig: Some(creds.signed_pre_key.signature.clone()),
    });

    payload
}

pub fn encode_signed_device_identity(
    account: &AdvSignedDeviceIdentity,
    include_signature_key: bool,
) -> Vec<u8> {
    let mut cloned = account.clone();
    if !include_signature_key
        || cloned
            .account_signature_key
            .as_ref()
            .is_none_or(|k| k.is_empty())
    {
        cloned.account_signature_key = None;
    }
    cloned.encode_to_vec()
}

pub fn configure_successful_pairing(
    stanza: &BinaryNode,
    adv_secret_key: &str,
    signed_identity_key: &KeyPair,
    existing_identities: &[SignalIdentity],
) -> Result<PairingResult, ValidateConnectionError> {
    let msg_id = stanza
        .attrs
        .get("id")
        .cloned()
        .ok_or(ValidateConnectionError::MissingAttribute("id"))?;

    let pair_success_node = get_binary_node_child(Some(stanza), "pair-success");
    let device_identity_node = get_binary_node_child(pair_success_node, "device-identity");
    let platform_node = get_binary_node_child(pair_success_node, "platform");
    let device_node = get_binary_node_child(pair_success_node, "device");
    let business_node = get_binary_node_child(pair_success_node, "biz");

    let (Some(device_identity_node), Some(device_node)) = (device_identity_node, device_node)
    else {
        return Err(ValidateConnectionError::MissingPairSuccessNodes);
    };

    let biz_name = business_node.and_then(|n| n.attrs.get("name").cloned());
    let jid = device_node
        .attrs
        .get("jid")
        .cloned()
        .ok_or(ValidateConnectionError::MissingAttribute("jid"))?;
    let lid = device_node.attrs.get("lid").cloned();

    let Some(BinaryNodeData::Bytes(identity_bytes)) = &device_identity_node.content else {
        return Err(ValidateConnectionError::MissingDeviceIdentityBytes);
    };

    let hmac_msg = AdvSignedDeviceIdentityHmac::decode(identity_bytes.as_slice())?;
    let details_bytes = hmac_msg
        .details
        .as_deref()
        .ok_or(ValidateConnectionError::MissingDeviceIdentityBytes)?;
    let hmac_bytes = hmac_msg
        .hmac
        .as_deref()
        .ok_or(ValidateConnectionError::InvalidAccountHmac)?;

    let mut hmac_input = Vec::new();
    if hmac_msg.account_type == Some(AdvEncryptionType::Hosted as i32) {
        hmac_input.extend_from_slice(&WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX);
    }
    hmac_input.extend_from_slice(details_bytes);

    let secret_bytes = BASE64.decode(adv_secret_key)?;
    let adv_sign = hmac_sign(&hmac_input, &secret_bytes, HmacVariant::Sha256)?;
    if adv_sign.as_slice() != hmac_bytes {
        return Err(ValidateConnectionError::InvalidAccountHmac);
    }

    let mut account = AdvSignedDeviceIdentity::decode(details_bytes)?;
    let account_signature_key = account
        .account_signature_key
        .as_deref()
        .ok_or(ValidateConnectionError::InvalidAccountSignature)?;
    let account_signature = account
        .account_signature
        .as_deref()
        .ok_or(ValidateConnectionError::InvalidAccountSignature)?;
    let device_details = account
        .details
        .as_deref()
        .ok_or(ValidateConnectionError::MissingDeviceIdentityBytes)?;

    let device_identity = AdvDeviceIdentity::decode(device_details)?;

    let account_sig_prefix = if device_identity.device_type == Some(AdvEncryptionType::Hosted as i32)
    {
        &WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
    } else {
        &WA_ADV_ACCOUNT_SIG_PREFIX
    };

    let mut account_msg = Vec::with_capacity(
        account_sig_prefix.len() + device_details.len() + signed_identity_key.public.len(),
    );
    account_msg.extend_from_slice(account_sig_prefix);
    account_msg.extend_from_slice(device_details);
    account_msg.extend_from_slice(&signed_identity_key.public);

    if !Curve::verify(account_signature_key, &account_msg, account_signature) {
        return Err(ValidateConnectionError::InvalidAccountSignature);
    }

    let mut device_msg = Vec::with_capacity(
        WA_ADV_DEVICE_SIG_PREFIX.len()
            + device_details.len()
            + signed_identity_key.public.len()
            + account_signature_key.len(),
    );
    device_msg.extend_from_slice(&WA_ADV_DEVICE_SIG_PREFIX);
    device_msg.extend_from_slice(device_details);
    device_msg.extend_from_slice(&signed_identity_key.public);
    device_msg.extend_from_slice(account_signature_key);

    account.device_signature = Some(Curve::sign(&signed_identity_key.private, &device_msg)?);

    let lid_str = lid
        .as_deref()
        .ok_or(ValidateConnectionError::MissingAttribute("lid"))?;
    let identity = create_signal_identity(lid_str, account_signature_key);
    let account_enc = encode_signed_device_identity(&account, false);

    let reply = BinaryNode {
        tag: "iq".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
            ("type".to_string(), "result".to_string()),
            ("id".to_string(), msg_id),
        ]),
        content: Some(BinaryNodeData::List(vec![BinaryNode {
            tag: "pair-device-sign".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "device-identity".to_string(),
                attrs: BinaryNodeAttributes::from([(
                    "key-index".to_string(),
                    device_identity.key_index.unwrap_or(0).to_string(),
                )]),
                content: Some(BinaryNodeData::Bytes(account_enc)),
            }])),
        }])),
    };

    let mut signal_identities = existing_identities.to_vec();
    signal_identities.push(identity);

    let creds = PairingCredsUpdate {
        account,
        me: ContactInfo {
            id: jid,
            name: biz_name,
            lid,
        },
        signal_identities,
        platform: platform_node.and_then(|n| n.attrs.get("name").cloned()),
    };

    Ok(PairingResult { creds, reply })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::crypto::signed_key_pair;

    #[test]
    fn test_generate_login_and_registration_nodes() {
        let config = SocketConfig::default();

        let login = generate_login_node("573001234567:2@s.whatsapp.net", &config).unwrap();
        assert_eq!(login.username, Some(573001234567));
        assert_eq!(login.device, Some(2));
        assert_eq!(login.passive, Some(true));

        let identity = Curve::generate_key_pair();
        let spk = signed_key_pair(&identity, 1).unwrap();
        let creds = SignalCreds {
            signed_identity_key: identity,
            signed_pre_key: spk,
            registration_id: 12345,
        };

        let reg = generate_registration_node(&creds, &config);
        assert_eq!(reg.passive, Some(false));
        let pairing = reg.device_pairing_data.unwrap();
        assert_eq!(pairing.e_regid, Some(vec![0, 0, 0x30, 0x39]));
        assert_eq!(pairing.e_keytype, Some(vec![5]));
        assert_eq!(pairing.e_skey_id, Some(vec![0, 0, 1]));
    }
}
