use super::binary_info::{BinaryInfo, WamValue};
use super::constants::{
    find_event, find_global, FLAG_BYTE, FLAG_EVENT, FLAG_EXTENDED, FLAG_FIELD, FLAG_GLOBAL,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WamEncodeError {
    #[error("unknown WAM global attribute: {0}")]
    UnknownGlobal(String),
    #[error("unknown WAM event: {0}")]
    UnknownEvent(String),
    #[error("unknown WAM prop '{prop}' for event '{event}'")]
    UnknownProp { event: String, prop: String },
    #[error("null value is only valid for global attributes")]
    InvalidNullValue,
}

fn get_header_bit_length(key: u16) -> usize {
    if key < 256 {
        2
    } else {
        3
    }
}

fn serialize_header(buf: &mut Vec<u8>, key: u16, flag: u8) {
    if key < 256 {
        buf.push(flag);
        buf.push(key as u8);
    } else {
        buf.push(flag | FLAG_BYTE);
        buf.extend_from_slice(&key.to_le_bytes());
    }
}

fn serialize_int(key: u16, value: i64, flag: u8) -> Vec<u8> {
    let header_len = get_header_bit_length(key);
    if value == 0 || value == 1 {
        let mut buf = Vec::with_capacity(header_len);
        serialize_header(&mut buf, key, flag | (((value + 1) as u8) << 4));
        buf
    } else if (-128..128).contains(&value) {
        let mut buf = Vec::with_capacity(header_len + 1);
        serialize_header(&mut buf, key, flag | (3 << 4));
        buf.push((value as i8) as u8);
        buf
    } else if (-32768..32768).contains(&value) {
        let mut buf = Vec::with_capacity(header_len + 2);
        serialize_header(&mut buf, key, flag | (4 << 4));
        buf.extend_from_slice(&(value as i16).to_le_bytes());
        buf
    } else if (-2_147_483_648..2_147_483_648).contains(&value) {
        let mut buf = Vec::with_capacity(header_len + 4);
        serialize_header(&mut buf, key, flag | (5 << 4));
        buf.extend_from_slice(&(value as i32).to_le_bytes());
        buf
    } else {
        let mut buf = Vec::with_capacity(header_len + 8);
        serialize_header(&mut buf, key, flag | (7 << 4));
        buf.extend_from_slice(&(value as f64).to_le_bytes());
        buf
    }
}

fn serialize_data(key: u16, value: &WamValue, flag: u8) -> Result<Vec<u8>, WamEncodeError> {
    let header_len = get_header_bit_length(key);
    match value {
        WamValue::Null => {
            if flag == FLAG_GLOBAL {
                let mut buf = Vec::with_capacity(header_len);
                serialize_header(&mut buf, key, flag);
                Ok(buf)
            } else {
                Err(WamEncodeError::InvalidNullValue)
            }
        }
        WamValue::Bool(b) => Ok(serialize_int(key, if *b { 1 } else { 0 }, flag)),
        WamValue::Int(v) => Ok(serialize_int(key, *v, flag)),
        WamValue::Float(v) => {
            if v.is_finite() && v.fract() == 0.0 && *v >= i64::MIN as f64 && *v <= i64::MAX as f64 {
                Ok(serialize_int(key, *v as i64, flag))
            } else {
                let mut buf = Vec::with_capacity(header_len + 8);
                serialize_header(&mut buf, key, flag | (7 << 4));
                buf.extend_from_slice(&v.to_le_bytes());
                Ok(buf)
            }
        }
        WamValue::String(s) => {
            let bytes = s.as_bytes();
            let utf8_len = bytes.len();
            if utf8_len < 256 {
                let mut buf = Vec::with_capacity(header_len + 1 + utf8_len);
                serialize_header(&mut buf, key, flag | (8 << 4));
                buf.push(utf8_len as u8);
                buf.extend_from_slice(bytes);
                Ok(buf)
            } else if utf8_len < 65536 {
                let mut buf = Vec::with_capacity(header_len + 2 + utf8_len);
                serialize_header(&mut buf, key, flag | (9 << 4));
                buf.extend_from_slice(&(utf8_len as u16).to_le_bytes());
                buf.extend_from_slice(bytes);
                Ok(buf)
            } else {
                let mut buf = Vec::with_capacity(header_len + 4 + utf8_len);
                serialize_header(&mut buf, key, flag | (10 << 4));
                buf.extend_from_slice(&(utf8_len as u32).to_le_bytes());
                buf.extend_from_slice(bytes);
                Ok(buf)
            }
        }
    }
}

fn encode_wam_header(binary_info: &mut BinaryInfo) {
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(b"WAM");
    header.push(binary_info.protocol_version);
    header.push(1);
    header.extend_from_slice(&binary_info.sequence.to_be_bytes());
    header.push(0);
    binary_info.buffer.push(header);
}

fn encode_global_attributes(
    buffer: &mut Vec<Vec<u8>>,
    globals: &[(String, WamValue)],
) -> Result<(), WamEncodeError> {
    for (key, value) in globals {
        let def = find_global(key).ok_or_else(|| WamEncodeError::UnknownGlobal(key.clone()))?;
        buffer.push(serialize_data(def.id, value, FLAG_GLOBAL)?);
    }
    Ok(())
}

pub fn encode_wam(binary_info: &mut BinaryInfo) -> Result<Vec<u8>, WamEncodeError> {
    binary_info.buffer.clear();
    encode_wam_header(binary_info);

    let events = binary_info.events.clone();
    for ev in &events {
        encode_global_attributes(&mut binary_info.buffer, &ev.globals)?;
        let event_def =
            find_event(&ev.name).ok_or_else(|| WamEncodeError::UnknownEvent(ev.name.clone()))?;

        let has_non_null = ev.props.iter().any(|(_, v)| !matches!(v, WamValue::Null));
        let event_flag = if has_non_null {
            FLAG_EVENT
        } else {
            FLAG_EVENT | FLAG_EXTENDED
        };
        binary_info.buffer.push(serialize_data(
            event_def.id,
            &WamValue::Int(-i64::from(event_def.weight)),
            event_flag,
        )?);

        for (i, (prop_key, prop_val)) in ev.props.iter().enumerate() {
            let prop_id = event_def
                .props
                .iter()
                .find(|(k, _)| *k == prop_key.as_str())
                .map(|(_, id)| *id)
                .ok_or_else(|| WamEncodeError::UnknownProp {
                    event: ev.name.clone(),
                    prop: prop_key.clone(),
                })?;
            let extended = i < ev.props.len() - 1;
            let field_flag = if extended {
                FLAG_EVENT
            } else {
                FLAG_FIELD | FLAG_EXTENDED
            };
            binary_info
                .buffer
                .push(serialize_data(prop_id, prop_val, field_flag)?);
        }
    }

    let total_size: usize = binary_info.buffer.iter().map(|b| b.len()).sum();
    let mut out = Vec::with_capacity(total_size);
    for chunk in &binary_info.buffer {
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wam::WamEventInput;

    #[test]
    fn test_encode_wam_header_and_event() {
        let mut info = BinaryInfo::new(
            7,
            vec![WamEventInput {
                name: "WamDroppedEvent".to_string(),
                props: vec![
                    ("droppedEventCode".to_string(), WamValue::Int(42)),
                    ("droppedEventCount".to_string(), WamValue::Int(1)),
                    ("isFromWamsys".to_string(), WamValue::Bool(true)),
                ],
                globals: Vec::new(),
            }],
        );

        let encoded = encode_wam(&mut info).unwrap();
        assert_eq!(&encoded[0..3], b"WAM");
        assert_eq!(encoded[3], 5);
        assert_eq!(encoded[4], 1);
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 7);
        assert_eq!(encoded[7], 0);
        assert!(encoded.len() > 8);
    }

    #[test]
    fn test_encode_wam_empty_props_event() {
        let mut info = BinaryInfo::new(
            1,
            vec![WamEventInput {
                name: "GroupJoinC".to_string(),
                props: Vec::new(),
                globals: Vec::new(),
            }],
        );

        let encoded = encode_wam(&mut info).unwrap();
        assert_eq!(&encoded[0..3], b"WAM");
        assert!(encoded.len() > 8);
    }
}
