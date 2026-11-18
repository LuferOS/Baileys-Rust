use super::constants::DEFAULT_CODING_OPTIONS;
use super::jid_utils::{jid_decode, FullJid};
use super::types::{BinaryNode, BinaryNodeCodingOptions, BinaryNodeData, BinaryNodeError, Tags};

#[derive(Clone, Copy)]
enum PackType {
    Nibble,
    Hex,
}

pub fn encode_binary_node(node: &BinaryNode) -> Result<Vec<u8>, BinaryNodeError> {
    encode_binary_node_with_opts(node, &DEFAULT_CODING_OPTIONS)
}

pub fn encode_binary_node_with_opts(
    node: &BinaryNode,
    opts: &BinaryNodeCodingOptions,
) -> Result<Vec<u8>, BinaryNodeError> {
    let mut buffer = vec![0u8];
    encode_binary_node_inner(node, opts, &mut buffer)?;
    Ok(buffer)
}

pub fn encode_binary_node_into(
    node: &BinaryNode,
    opts: &BinaryNodeCodingOptions,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    encode_binary_node_inner(node, opts, buffer)
}

fn push_int(value: u32, n: usize, little_endian: bool, buffer: &mut Vec<u8>) {
    for i in 0..n {
        let cur_shift = if little_endian { i } else { n - 1 - i };
        buffer.push(((value >> (cur_shift * 8)) & 0xff) as u8);
    }
}

fn push_int16(value: u16, buffer: &mut Vec<u8>) {
    buffer.push(((value >> 8) & 0xff) as u8);
    buffer.push((value & 0xff) as u8);
}

fn push_int20(value: u32, buffer: &mut Vec<u8>) {
    buffer.push(((value >> 16) & 0x0f) as u8);
    buffer.push(((value >> 8) & 0xff) as u8);
    buffer.push((value & 0xff) as u8);
}

fn write_byte_length(
    length: usize,
    tags: &Tags,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    if (length as u64) >= 4_294_967_296 {
        return Err(BinaryNodeError::StringTooLarge(length));
    }

    if length >= (1 << 20) {
        buffer.push(tags.binary_32);
        push_int(length as u32, 4, false, buffer);
    } else if length >= 256 {
        buffer.push(tags.binary_20);
        push_int20(length as u32, buffer);
    } else {
        buffer.push(tags.binary_8);
        buffer.push(length as u8);
    }

    Ok(())
}

fn write_string_raw(
    s: &str,
    tags: &Tags,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    let bytes = s.as_bytes();
    write_byte_length(bytes.len(), tags, buffer)?;
    buffer.extend_from_slice(bytes);
    Ok(())
}

fn pack_nibble(b: u8) -> Result<u8, BinaryNodeError> {
    match b {
        b'-' => Ok(10),
        b'.' => Ok(11),
        0 => Ok(15),
        b'0'..=b'9' => Ok(b - b'0'),
        _ => Err(BinaryNodeError::InvalidNibbleByte(b)),
    }
}

fn pack_hex(b: u8) -> Result<u8, BinaryNodeError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        0 => Ok(15),
        _ => Err(BinaryNodeError::InvalidHexByte(b)),
    }
}

fn write_packed_bytes(
    s: &str,
    pack_type: PackType,
    tags: &Tags,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    let bytes = s.as_bytes();
    if bytes.len() > tags.packed_max as usize {
        return Err(BinaryNodeError::TooManyPackedBytes);
    }

    buffer.push(match pack_type {
        PackType::Nibble => tags.nibble_8,
        PackType::Hex => tags.hex_8,
    });

    let mut rounded_length = bytes.len().div_ceil(2) as u8;
    if bytes.len() % 2 != 0 {
        rounded_length |= 128;
    }
    buffer.push(rounded_length);

    let pack_fn = match pack_type {
        PackType::Nibble => pack_nibble,
        PackType::Hex => pack_hex,
    };

    let half_len = bytes.len() / 2;
    for i in 0..half_len {
        let v1 = pack_fn(bytes[2 * i])?;
        let v2 = pack_fn(bytes[2 * i + 1])?;
        buffer.push((v1 << 4) | v2);
    }

    if bytes.len() % 2 != 0 {
        let v1 = pack_fn(bytes[bytes.len() - 1])?;
        let v2 = pack_fn(0)?;
        buffer.push((v1 << 4) | v2);
    }

    Ok(())
}

fn is_nibble(s: &str, packed_max: u8) -> bool {
    if s.is_empty() || s.len() > packed_max as usize {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn is_hex(s: &str, packed_max: u8) -> bool {
    if s.is_empty() || s.len() > packed_max as usize {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn write_jid(
    jid: &FullJid,
    opts: &BinaryNodeCodingOptions,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    if let Some(device) = jid.device {
        buffer.push(opts.tags.ad_jid);
        buffer.push(jid.domain_type.unwrap_or(0) as u8);
        buffer.push(device as u8);
        write_string(Some(&jid.user), opts, buffer)?;
    } else {
        buffer.push(opts.tags.jid_pair);
        if !jid.user.is_empty() {
            write_string(Some(&jid.user), opts, buffer)?;
        } else {
            buffer.push(opts.tags.list_empty);
        }
        write_string(Some(jid.server.as_str()), opts, buffer)?;
    }
    Ok(())
}

fn write_string(
    s: Option<&str>,
    opts: &BinaryNodeCodingOptions,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    let Some(s) = s else {
        buffer.push(opts.tags.list_empty);
        return Ok(());
    };

    if s.is_empty() {
        return write_string_raw(s, &opts.tags, buffer);
    }

    if let Some(token_index) = opts.token_map.get(s) {
        if let Some(dict) = token_index.dict {
            buffer.push(opts.tags.dictionary_0 + dict);
        }
        buffer.push(token_index.index);
    } else if is_nibble(s, opts.tags.packed_max) {
        write_packed_bytes(s, PackType::Nibble, &opts.tags, buffer)?;
    } else if is_hex(s, opts.tags.packed_max) {
        write_packed_bytes(s, PackType::Hex, &opts.tags, buffer)?;
    } else if let Some(decoded_jid) = jid_decode(s) {
        write_jid(&decoded_jid, opts, buffer)?;
    } else {
        write_string_raw(s, &opts.tags, buffer)?;
    }

    Ok(())
}

fn write_list_start(list_size: usize, tags: &Tags, buffer: &mut Vec<u8>) {
    if list_size == 0 {
        buffer.push(tags.list_empty);
    } else if list_size < 256 {
        buffer.push(tags.list_8);
        buffer.push(list_size as u8);
    } else {
        buffer.push(tags.list_16);
        push_int16(list_size as u16, buffer);
    }
}

fn encode_binary_node_inner(
    node: &BinaryNode,
    opts: &BinaryNodeCodingOptions,
    buffer: &mut Vec<u8>,
) -> Result<(), BinaryNodeError> {
    if node.tag.is_empty() {
        return Err(BinaryNodeError::EmptyTag);
    }

    let list_size = 2 * node.attrs.len() + 1 + usize::from(node.content.is_some());
    write_list_start(list_size, &opts.tags, buffer);
    write_string(Some(&node.tag), opts, buffer)?;

    for (key, value) in &node.attrs {
        write_string(Some(key), opts, buffer)?;
        write_string(Some(value), opts, buffer)?;
    }

    match &node.content {
        Some(BinaryNodeData::String(s)) => {
            write_string(Some(s), opts, buffer)?;
        }
        Some(BinaryNodeData::Bytes(bytes)) => {
            write_byte_length(bytes.len(), &opts.tags, buffer)?;
            buffer.extend_from_slice(bytes);
        }
        Some(BinaryNodeData::List(items)) => {
            let valid_items: Vec<&BinaryNode> = items.iter().filter(|i| !i.tag.is_empty()).collect();
            write_list_start(valid_items.len(), &opts.tags, buffer);
            for item in valid_items {
                encode_binary_node_inner(item, opts, buffer)?;
            }
        }
        None => {}
    }

    Ok(())
}
