use crate::proto::{Message, MessageContextInfo};
use crate::types::WaMessageKey;
use crate::utils::crypto::{hkdf, hmac_sign, HmacVariant};
use crate::wa_binary::{BinaryNode, BinaryNodeAttributes, BinaryNodeData};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::OnceLock;

const ENC_SECRET_REPORT_TOKEN: &[u8] = b"Report Token";
const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_BYTES: u8 = 2;
const WIRE_FIXED32: u8 = 5;

struct CompiledReportingField {
    m: bool,
    children: Option<HashMap<u32, CompiledReportingField>>,
}

struct ReportingFieldDef {
    f: u32,
    m: bool,
    s: &'static [ReportingFieldDef],
}

const fn rf(f: u32) -> ReportingFieldDef {
    ReportingFieldDef { f, m: false, s: &[] }
}

const fn rfm(f: u32) -> ReportingFieldDef {
    ReportingFieldDef { f, m: true, s: &[] }
}

const fn rfs(f: u32, s: &'static [ReportingFieldDef]) -> ReportingFieldDef {
    ReportingFieldDef { f, m: false, s }
}

const SUB_21_22: &[ReportingFieldDef] = &[rf(21), rf(22)];
const SUB_1_2: &[ReportingFieldDef] = &[rf(1), rf(2)];
const SUB_1M: &[ReportingFieldDef] = &[rfm(1)];
const SUB_POLL: &[ReportingFieldDef] = &[
    rf(2),
    rfs(3, SUB_1_2),
    rfs(5, SUB_21_22),
    rfs(8, SUB_1_2),
];

const REPORTING_FIELDS: &[ReportingFieldDef] = &[
    rf(1),
    rfs(3, &[rf(2), rf(3), rf(8), rf(11), rfs(17, SUB_21_22), rf(25)]),
    rfs(4, &[rf(1), rf(16), rfs(17, SUB_21_22)]),
    rfs(5, &[rf(3), rf(4), rf(5), rf(16), rfs(17, SUB_21_22)]),
    rfs(6, &[rf(1), rfs(17, SUB_21_22), rf(30)]),
    rfs(7, &[rf(2), rf(7), rf(10), rfs(17, SUB_21_22), rf(20)]),
    rfs(8, &[rf(2), rf(7), rf(9), rfs(17, SUB_21_22), rf(21)]),
    rfs(9, &[rf(2), rf(6), rf(7), rf(13), rfs(17, SUB_21_22), rf(20)]),
    rfs(12, &[rf(1), rf(2), rfm(14), rf(15)]),
    rfs(18, &[rf(6), rf(16), rfs(17, SUB_21_22)]),
    rfs(26, &[rf(4), rf(5), rf(8), rf(13), rfs(17, SUB_21_22)]),
    rfs(28, &[rf(1), rf(2), rf(4), rf(5), rf(6), rfs(7, SUB_21_22)]),
    rfs(37, SUB_1M),
    rfs(49, SUB_POLL),
    rfs(53, SUB_1M),
    rfs(55, SUB_1M),
    rfs(58, SUB_1M),
    rfs(59, SUB_1M),
    rfs(60, SUB_POLL),
    rfs(64, SUB_POLL),
    rfs(66, &[rf(2), rf(6), rf(7), rf(13), rfs(17, SUB_21_22), rf(20)]),
    rfs(74, SUB_1M),
    rfs(87, SUB_1M),
    rfs(88, &[rf(1), rfs(2, &[rf(1)]), rfs(3, SUB_21_22)]),
    rfs(92, SUB_1M),
    rfs(93, SUB_1M),
    rfs(94, SUB_1M),
];

fn compile_fields(defs: &[ReportingFieldDef]) -> HashMap<u32, CompiledReportingField> {
    let mut map = HashMap::with_capacity(defs.len());
    for def in defs {
        let children = if def.s.is_empty() {
            None
        } else {
            Some(compile_fields(def.s))
        };
        map.insert(def.f, CompiledReportingField { m: def.m, children });
    }
    map
}

fn compiled_reporting_fields() -> &'static HashMap<u32, CompiledReportingField> {
    static FIELDS: OnceLock<HashMap<u32, CompiledReportingField>> = OnceLock::new();
    FIELDS.get_or_init(|| compile_fields(REPORTING_FIELDS))
}

fn empty_field_map() -> &'static HashMap<u32, CompiledReportingField> {
    static EMPTY: OnceLock<HashMap<u32, CompiledReportingField>> = OnceLock::new();
    EMPTY.get_or_init(HashMap::new)
}

pub fn should_include_reporting_token(message: &Message) -> bool {
    message.reaction_message.is_none()
        && message.enc_reaction_message.is_none()
        && message.enc_event_response_message.is_none()
        && message.poll_update_message.is_none()
}

fn generate_msg_secret_key(
    modification_type: &[u8],
    orig_msg_id: &str,
    orig_msg_sender: &str,
    modification_sender: &str,
    orig_msg_secret: &[u8],
) -> Option<Vec<u8>> {
    let mut info = Vec::with_capacity(
        orig_msg_id.len()
            + orig_msg_sender.len()
            + modification_sender.len()
            + modification_type.len(),
    );
    info.extend_from_slice(orig_msg_id.as_bytes());
    info.extend_from_slice(orig_msg_sender.as_bytes());
    info.extend_from_slice(modification_sender.as_bytes());
    info.extend_from_slice(modification_type);

    hkdf(orig_msg_secret, 32, None, &info).ok()
}

fn decode_varint(buffer: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut bytes = 0usize;
    let mut shift = 0u32;

    while offset + bytes < buffer.len() {
        let current = buffer[offset + bytes];
        value |= u64::from(current & 0x7f) << shift;
        bytes += 1;

        if (current & 0x80) == 0 {
            return Some((value, bytes));
        }

        shift += 7;
        if shift > 63 {
            return None;
        }
    }

    None
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut parts = Vec::new();
    while value > 0x7f {
        parts.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
    parts.push(value as u8);
    parts
}

fn extract_reporting_token_content(
    data: &[u8],
    cfg: &HashMap<u32, CompiledReportingField>,
) -> Option<Vec<u8>> {
    let mut out: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        let (tag_val, tag_bytes) = decode_varint(data, i)?;
        let field_num = (tag_val >> 3) as u32;
        let wire_type = (tag_val & 0x07) as u8;
        let field_start = i;
        i += tag_bytes;

        let field_cfg = cfg.get(&field_num);

        match wire_type {
            WIRE_VARINT => {
                let (_, v_bytes) = decode_varint(data, i)?;
                let end = i + v_bytes;
                if end > data.len() {
                    return None;
                }
                if field_cfg.is_some() {
                    out.push((field_num, data[field_start..end].to_vec()));
                }
                i = end;
            }
            WIRE_FIXED64 => {
                let end = i + 8;
                if end > data.len() {
                    return None;
                }
                if field_cfg.is_some() {
                    out.push((field_num, data[field_start..end].to_vec()));
                }
                i = end;
            }
            WIRE_FIXED32 => {
                let end = i + 4;
                if end > data.len() {
                    return None;
                }
                if field_cfg.is_some() {
                    out.push((field_num, data[field_start..end].to_vec()));
                }
                i = end;
            }
            WIRE_BYTES => {
                let (len_val, len_bytes) = decode_varint(data, i)?;
                let val_start = i + len_bytes;
                let val_end = val_start.checked_add(len_val as usize)?;
                if val_end > data.len() {
                    return None;
                }

                if let Some(fcfg) = field_cfg {
                    if fcfg.m || fcfg.children.is_some() {
                        let sub_cfg = fcfg.children.as_ref().unwrap_or_else(|| empty_field_map());
                        let sub = extract_reporting_token_content(&data[val_start..val_end], sub_cfg)?;
                        if !sub.is_empty() {
                            let new_tag = encode_varint(tag_val);
                            let new_len = encode_varint(sub.len() as u64);
                            let mut combined =
                                Vec::with_capacity(new_tag.len() + new_len.len() + sub.len());
                            combined.extend_from_slice(&new_tag);
                            combined.extend_from_slice(&new_len);
                            combined.extend_from_slice(&sub);
                            out.push((field_num, combined));
                        }
                    } else {
                        out.push((field_num, data[field_start..val_end].to_vec()));
                    }
                }
                i = val_end;
            }
            _ => return None,
        }
    }

    if out.is_empty() {
        return Some(Vec::new());
    }

    out.sort_by_key(|(num, _)| *num);
    let total_len: usize = out.iter().map(|(_, b)| b.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for (_, bytes) in out {
        result.extend_from_slice(&bytes);
    }
    Some(result)
}

pub fn get_message_reporting_token(
    msg_protobuf: &[u8],
    message: &Message,
    key: &WaMessageKey,
) -> Option<BinaryNode> {
    let mci: &MessageContextInfo = message.message_context_info.as_ref().map(|c| Borrow::borrow(c))?;
    let msg_secret = mci.message_secret.as_deref()?;
    let msg_id = key.id.as_deref()?;
    let remote_jid = key.remote_jid.as_deref()?;

    let from_me = key.from_me == Some(true);
    let from = if from_me {
        remote_jid
    } else {
        key.participant.as_deref().unwrap_or(remote_jid)
    };
    let to = if from_me {
        key.participant.as_deref().unwrap_or(remote_jid)
    } else {
        remote_jid
    };

    let reporting_secret =
        generate_msg_secret_key(ENC_SECRET_REPORT_TOKEN, msg_id, from, to, msg_secret)?;
    let content = extract_reporting_token_content(msg_protobuf, compiled_reporting_fields())?;
    if content.is_empty() {
        return None;
    }

    let mac = hmac_sign(&content, &reporting_secret, HmacVariant::Sha256).ok()?;
    let reporting_token = mac[..16].to_vec();

    Some(BinaryNode {
        tag: "reporting".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::List(vec![BinaryNode {
            tag: "reporting_token".to_string(),
            attrs: BinaryNodeAttributes::from([("v".to_string(), "2".to_string())]),
            content: Some(BinaryNodeData::Bytes(reporting_token)),
        }])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::ReactionMessage;
    use prost::Message as ProstMessage;

    #[test]
    fn test_reporting_token_generation_and_filtering() {
        let msg = Message {
            conversation: Some("hola reporte".to_string()),
            message_context_info: Some(
                MessageContextInfo {
                    message_secret: Some(vec![7u8; 32]),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        assert!(should_include_reporting_token(&msg));

        let key = WaMessageKey {
            id: Some("MSG_REP_1".to_string()),
            remote_jid: Some("573001111111@s.whatsapp.net".to_string()),
            from_me: Some(true),
            ..Default::default()
        };
        let encoded = msg.encode_to_vec();
        let node = get_message_reporting_token(&encoded, &msg, &key).unwrap();
        assert_eq!(node.tag, "reporting");
        if let Some(BinaryNodeData::List(children)) = node.content {
            assert_eq!(children[0].tag, "reporting_token");
            assert_eq!(children[0].attrs.get("v").map(|s| s.as_str()), Some("2"));
            if let Some(BinaryNodeData::Bytes(token)) = &children[0].content {
                assert_eq!(token.len(), 16);
            } else {
                panic!("expected token bytes");
            }
        } else {
            panic!("expected children list");
        }

        let reaction_msg = Message {
            reaction_message: Some(ReactionMessage::default().into()),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&reaction_msg));
    }
}
