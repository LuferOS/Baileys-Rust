use crate::proto::{Message, MessageKey};
use crate::types::{DisconnectReason, WaMessageKey};
use crate::utils::crypto::sha256;
use crate::wa_binary::{get_all_binary_node_children, BinaryNode};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prost::Message as ProstMessage;
use rand::{rngs::OsRng, RngCore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CROCKFORD_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";
const UNEXPECTED_SERVER_CODE_TEXT: &str = "Unexpected server response: ";
pub const FALLBACK_BAILEYS_VERSION: [u32; 3] = [2, 3000, 1043857760];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaVersionFetchResult {
    pub version: [u32; 3],
    pub is_latest: bool,
    pub error: Option<String>,
}

pub fn is_string_null_or_empty(value: Option<&str>) -> bool {
    value.is_none_or(|s| s.is_empty())
}

pub fn is_wa_business_platform(platform: &str) -> bool {
    platform == "smbi" || platform == "smba"
}

pub async fn delay(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

pub fn generate_md_tag_prefix() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    let p1 = u16::from_be_bytes([bytes[0], bytes[1]]);
    let p2 = u16::from_be_bytes([bytes[2], bytes[3]]);
    format!("{}.{}-", p1, p2)
}

pub fn bytes_to_crockford(buffer: &[u8]) -> String {
    let mut value: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = String::new();

    for &byte in buffer {
        value = (value << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            let idx = ((value >> (bit_count - 5)) & 31) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
            bit_count -= 5;
        }
    }

    if bit_count > 0 {
        let idx = ((value << (5 - bit_count)) & 31) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }

    out
}

pub fn pad_random_max_16(msg: &[u8]) -> Vec<u8> {
    let mut pad_byte = [0u8; 1];
    OsRng.fill_bytes(&mut pad_byte);
    let pad_len = usize::from((pad_byte[0] & 0x0f) + 1);
    let mut out = Vec::with_capacity(msg.len() + pad_len);
    out.extend_from_slice(msg);
    out.resize(msg.len() + pad_len, pad_len as u8);
    out
}

pub fn unpad_random_max_16(buf: &[u8]) -> Result<&[u8], &'static str> {
    if buf.is_empty() {
        return Err("unpadPkcs7 given empty bytes");
    }
    let pad_len = usize::from(*buf.last().unwrap());
    if pad_len == 0 || pad_len > buf.len() {
        return Err("unpad invalid pad length");
    }
    Ok(&buf[..buf.len() - pad_len])
}

pub fn encode_wa_message(message: &Message) -> Vec<u8> {
    pad_random_max_16(&message.encode_to_vec())
}

pub fn encode_newsletter_message(message: &Message) -> Vec<u8> {
    message.encode_to_vec()
}

pub fn generate_participant_hash_v2(participants: &[String]) -> String {
    let mut sorted = participants.to_vec();
    sorted.sort();
    let joined = sorted.join("");
    let hash_b64 = BASE64.encode(sha256(joined.as_bytes()));
    format!("2:{}", &hash_b64[..6])
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn generate_message_id() -> String {
    let mut rand_buf = [0u8; 18];
    OsRng.fill_bytes(&mut rand_buf);
    let mut hex = String::with_capacity(40);
    hex.push_str("3EB0");
    for &b in &rand_buf {
        hex.push_str(&format!("{:02X}", b));
    }
    hex
}

pub fn generate_message_id_v2(user_id: Option<&str>) -> String {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&unix_timestamp_seconds().to_be_bytes());
    if let Some(uid) = user_id {
        if let Some(user) = uid.split('@').next() {
            data.extend_from_slice(user.as_bytes());
            data.extend_from_slice(b"@c.us");
        }
    }
    let mut rand_buf = [0u8; 16];
    OsRng.fill_bytes(&mut rand_buf);
    data.extend_from_slice(&rand_buf);

    let hash = sha256(&data);
    let mut hex = String::with_capacity(22);
    hex.push_str("3EB0");
    for &b in &hash[..9] {
        hex.push_str(&format!("{:02X}", b));
    }
    hex
}

pub fn get_key_author(key: Option<&WaMessageKey>, me_id: Option<&str>) -> String {
    let Some(key) = key else {
        return String::new();
    };
    if key.from_me == Some(true) {
        return me_id.unwrap_or("me").to_string();
    }
    key.participant_alt
        .clone()
        .or_else(|| key.remote_jid_alt.clone())
        .or_else(|| key.participant.clone())
        .or_else(|| key.remote_jid.clone())
        .unwrap_or_default()
}

pub fn get_proto_key_author(key: Option<&MessageKey>, me_id: Option<&str>) -> String {
    let Some(key) = key else {
        return String::new();
    };
    if key.from_me == Some(true) {
        return me_id.unwrap_or("me").to_string();
    }
    key.participant
        .clone()
        .or_else(|| key.remote_jid.clone())
        .unwrap_or_default()
}

pub fn get_error_code_from_stream_error(node: &BinaryNode) -> (String, u16) {
    let reason_node = get_all_binary_node_children(node).first();
    let mut reason = reason_node
        .map(|n| n.tag.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let mapped_status = match reason.as_str() {
        "conflict" | "replaced" => Some(DisconnectReason::ConnectionReplaced as u16),
        "device_removed" | "logged_out" => Some(DisconnectReason::LoggedOut as u16),
        "restart" => Some(DisconnectReason::RestartRequired as u16),
        _ => None,
    };

    let status_code = node
        .attrs
        .get("code")
        .and_then(|c| c.parse::<u16>().ok())
        .or(mapped_status)
        .unwrap_or(DisconnectReason::BadSession as u16);

    if status_code == DisconnectReason::RestartRequired as u16 {
        reason = "restart required".to_string();
    }

    (reason, status_code)
}

pub fn get_code_from_ws_error(error_message: &str, error_code: Option<&str>) -> u16 {
    if let Some(pos) = error_message.find(UNEXPECTED_SERVER_CODE_TEXT) {
        let rest = &error_message[pos + UNEXPECTED_SERVER_CODE_TEXT.len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(code) = digits.parse::<u16>() {
            if code >= 400 {
                return code;
            }
        }
    } else if error_code.is_some_and(|c| c.starts_with('E'))
        || error_message.contains("timed out")
    {
        return 408;
    }

    500
}

pub fn parse_baileys_version_from_source(text: &str) -> Option<[u32; 3]> {
    let marker = "const version = [";
    let start = text.find(marker)? + marker.len();
    let end = text[start..].find(']')? + start;
    let parts: Vec<u32> = text[start..end]
        .split(',')
        .filter_map(|p| p.trim().parse::<u32>().ok())
        .collect();
    if parts.len() == 3 {
        Some([parts[0], parts[1], parts[2]])
    } else {
        None
    }
}

pub fn parse_wa_web_revision_from_sw(data: &str) -> Option<[u32; 3]> {
    let marker = "client_revision";
    let mut search = data;
    while let Some(pos) = search.find(marker) {
        let after = &search[pos + marker.len()..];
        let trimmed = after
            .trim_start_matches(|c: char| c == '\\' || c == '"' || c == '\'' || c.is_ascii_whitespace());
        if let Some(after_colon) = trimmed.strip_prefix(':') {
            let num_part = after_colon.trim_start();
            let digits: String = num_part
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(rev) = digits.parse::<u32>() {
                return Some([2, 3000, rev]);
            }
        }
        search = after;
    }
    None
}

pub async fn fetch_latest_baileys_version(timeout_ms: Option<u64>) -> WaVersionFetchResult {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let url = "https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/src/Defaults/index.ts";
    let mut builder = reqwest::Client::builder();
    if let Some(ms) = timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(err) => {
            return WaVersionFetchResult {
                version: FALLBACK_BAILEYS_VERSION,
                is_latest: false,
                error: Some(err.to_string()),
            };
        }
    };

    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(text) => match parse_baileys_version_from_source(&text) {
                Some(version) => WaVersionFetchResult {
                    version,
                    is_latest: true,
                    error: None,
                },
                None => WaVersionFetchResult {
                    version: FALLBACK_BAILEYS_VERSION,
                    is_latest: false,
                    error: Some("Could not parse version from Defaults/index.ts".to_string()),
                },
            },
            Err(err) => WaVersionFetchResult {
                version: FALLBACK_BAILEYS_VERSION,
                is_latest: false,
                error: Some(err.to_string()),
            },
        },
        Ok(resp) => WaVersionFetchResult {
            version: FALLBACK_BAILEYS_VERSION,
            is_latest: false,
            error: Some(format!("HTTP {}", resp.status())),
        },
        Err(err) => WaVersionFetchResult {
            version: FALLBACK_BAILEYS_VERSION,
            is_latest: false,
            error: Some(err.to_string()),
        },
    }
}

pub async fn fetch_latest_wa_web_version(timeout_ms: Option<u64>) -> WaVersionFetchResult {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let url = "https://web.whatsapp.com/sw.js";
    let mut builder = reqwest::Client::builder();
    if let Some(ms) = timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(err) => {
            return WaVersionFetchResult {
                version: FALLBACK_BAILEYS_VERSION,
                is_latest: false,
                error: Some(err.to_string()),
            };
        }
    };

    let req = client
        .get(url)
        .header("sec-fetch-site", "none")
        .header(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        );

    match req.send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(text) => match parse_wa_web_revision_from_sw(&text) {
                Some(version) => WaVersionFetchResult {
                    version,
                    is_latest: true,
                    error: None,
                },
                None => WaVersionFetchResult {
                    version: FALLBACK_BAILEYS_VERSION,
                    is_latest: false,
                    error: Some(
                        "Could not find client revision in the fetched content".to_string(),
                    ),
                },
            },
            Err(err) => WaVersionFetchResult {
                version: FALLBACK_BAILEYS_VERSION,
                is_latest: false,
                error: Some(err.to_string()),
            },
        },
        Ok(resp) => WaVersionFetchResult {
            version: FALLBACK_BAILEYS_VERSION,
            is_latest: false,
            error: Some(format!("HTTP {}", resp.status())),
        },
        Err(err) => WaVersionFetchResult {
            version: FALLBACK_BAILEYS_VERSION,
            is_latest: false,
            error: Some(err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wa_binary::{BinaryNodeAttributes, BinaryNodeData};

    #[test]
    fn test_crockford_length_for_pairing_code() {
        let code = bytes_to_crockford(&[0x12, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| CROCKFORD_ALPHABET.contains(&b)));
    }

    #[test]
    fn test_md_tag_prefix_format() {
        let prefix = generate_md_tag_prefix();
        assert!(prefix.ends_with('-'));
        assert!(prefix.contains('.'));
    }

    #[test]
    fn test_generate_message_ids_and_phash() {
        let id_v1 = generate_message_id();
        assert_eq!(id_v1.len(), 40);
        assert!(id_v1.starts_with("3EB0"));

        let id = generate_message_id_v2(Some("573001234567@s.whatsapp.net"));
        assert_eq!(id.len(), 22);
        assert!(id.starts_with("3EB0"));

        let h1 = generate_participant_hash_v2(&[
            "b@s.whatsapp.net".to_string(),
            "a@s.whatsapp.net".to_string(),
        ]);
        let h2 = generate_participant_hash_v2(&[
            "a@s.whatsapp.net".to_string(),
            "b@s.whatsapp.net".to_string(),
        ]);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("2:"));
        assert_eq!(h1.len(), 8);
    }

    #[test]
    fn test_pad_unpad_random_max_16() {
        let raw = b"hola mundo whatsapp";
        let padded = pad_random_max_16(raw);
        assert!(padded.len() > raw.len());
        assert!(padded.len() <= raw.len() + 16);
        let unpadded = unpad_random_max_16(&padded).unwrap();
        assert_eq!(unpadded, raw);
    }

    #[test]
    fn test_stream_error_ws_code_and_version_parsers() {
        let node = BinaryNode {
            tag: "stream:error".to_string(),
            attrs: BinaryNodeAttributes::from([("code".to_string(), "515".to_string())]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "conflict".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: None,
            }])),
        };
        let (reason, code) = get_error_code_from_stream_error(&node);
        assert_eq!(code, 515);
        assert_eq!(reason, "restart required");

        assert_eq!(
            get_code_from_ws_error("Unexpected server response: 503", None),
            503
        );
        assert_eq!(get_code_from_ws_error("request timed out", None), 408);
        assert_eq!(get_code_from_ws_error("other", Some("ENOTFOUND")), 408);
        assert!(is_wa_business_platform("smba"));
        assert!(!is_wa_business_platform("web"));

        let src = "import x\nconst version = [2, 3000, 1043857760]\n";
        assert_eq!(
            parse_baileys_version_from_source(src),
            Some([2, 3000, 1043857760])
        );

        let sw = r#"self.__sw = {\"client_revision\": 1043999111};"#;
        assert_eq!(
            parse_wa_web_revision_from_sw(sw),
            Some([2, 3000, 1043999111])
        );
    }
}
