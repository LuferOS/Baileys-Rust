use crate::types::DisconnectReason;
use crate::wa_binary::{get_all_binary_node_children, BinaryNode};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

const CROCKFORD_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

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

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
    fn test_stream_error_code() {
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
    }
}
