use super::constants::DEFAULT_CODING_OPTIONS;
use super::jid_utils::{jid_encode, JidServer, WaJidDomains};
use super::types::{BinaryNode, BinaryNodeAttributes, BinaryNodeCodingOptions, BinaryNodeData, BinaryNodeError};
use flate2::read::ZlibDecoder;
use std::io::Read;

pub fn decompressing_if_required(buffer: &[u8]) -> Result<Vec<u8>, BinaryNodeError> {
    if buffer.is_empty() {
        return Err(BinaryNodeError::EndOfStream);
    }

    if (buffer[0] & 2) != 0 {
        let mut decoder = ZlibDecoder::new(&buffer[1..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    } else {
        Ok(buffer[1..].to_vec())
    }
}

pub fn decode_binary_node(buff: &[u8]) -> Result<BinaryNode, BinaryNodeError> {
    let decomp_buff = decompressing_if_required(buff)?;
    let mut index = 0;
    decode_decompressed_binary_node(&decomp_buff, &DEFAULT_CODING_OPTIONS, &mut index)
}

pub fn decode_decompressed_binary_node(
    buffer: &[u8],
    opts: &BinaryNodeCodingOptions,
    index: &mut usize,
) -> Result<BinaryNode, BinaryNodeError> {
    let mut decoder = Decoder {
        buffer,
        opts,
        index,
    };
    decoder.read_node()
}

struct Decoder<'a> {
    buffer: &'a [u8],
    opts: &'a BinaryNodeCodingOptions,
    index: &'a mut usize,
}

impl<'a> Decoder<'a> {
    fn check_eos(&self, length: usize) -> Result<(), BinaryNodeError> {
        if *self.index + length > self.buffer.len() {
            return Err(BinaryNodeError::EndOfStream);
        }
        Ok(())
    }

    fn next(&mut self) -> u8 {
        let value = self.buffer[*self.index];
        *self.index += 1;
        value
    }

    fn read_byte(&mut self) -> Result<u8, BinaryNodeError> {
        self.check_eos(1)?;
        Ok(self.next())
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], BinaryNodeError> {
        self.check_eos(n)?;
        let value = &self.buffer[*self.index..*self.index + n];
        *self.index += n;
        Ok(value)
    }

    fn read_string_from_chars(&mut self, length: usize) -> Result<String, BinaryNodeError> {
        let bytes = self.read_bytes(length)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn read_int(&mut self, n: usize, little_endian: bool) -> Result<u32, BinaryNodeError> {
        self.check_eos(n)?;
        let mut val: u32 = 0;
        for i in 0..n {
            let shift = if little_endian { i } else { n - 1 - i };
            val |= u32::from(self.next()) << (shift * 8);
        }
        Ok(val)
    }

    fn read_int20(&mut self) -> Result<usize, BinaryNodeError> {
        self.check_eos(3)?;
        let b0 = usize::from(self.next() & 15) << 16;
        let b1 = usize::from(self.next()) << 8;
        let b2 = usize::from(self.next());
        Ok(b0 + b1 + b2)
    }

    fn unpack_hex(value: u8) -> Result<u8, BinaryNodeError> {
        match value {
            0..=9 => Ok(b'0' + value),
            10..=15 => Ok(b'A' + value - 10),
            _ => Err(BinaryNodeError::InvalidHexValue(value)),
        }
    }

    fn unpack_nibble(value: u8) -> Result<u8, BinaryNodeError> {
        match value {
            0..=9 => Ok(b'0' + value),
            10 => Ok(b'-'),
            11 => Ok(b'.'),
            15 => Ok(0),
            _ => Err(BinaryNodeError::InvalidNibbleValue(value)),
        }
    }

    fn unpack_byte(&self, tag: u8, value: u8) -> Result<u8, BinaryNodeError> {
        if tag == self.opts.tags.nibble_8 {
            Self::unpack_nibble(value)
        } else if tag == self.opts.tags.hex_8 {
            Self::unpack_hex(value)
        } else {
            Err(BinaryNodeError::UnknownPackedTag(tag))
        }
    }

    fn read_packed8(&mut self, tag: u8) -> Result<String, BinaryNodeError> {
        let start_byte = self.read_byte()?;
        let mut value = String::new();

        for _ in 0..(start_byte & 127) {
            let cur_byte = self.read_byte()?;
            value.push(self.unpack_byte(tag, (cur_byte & 0xf0) >> 4)? as char);
            value.push(self.unpack_byte(tag, cur_byte & 0x0f)? as char);
        }

        if (start_byte >> 7) != 0 {
            value.pop();
        }

        Ok(value)
    }

    fn is_list_tag(&self, tag: u8) -> bool {
        tag == self.opts.tags.list_empty
            || tag == self.opts.tags.list_8
            || tag == self.opts.tags.list_16
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize, BinaryNodeError> {
        let tags = &self.opts.tags;
        if tag == tags.list_empty {
            Ok(0)
        } else if tag == tags.list_8 {
            Ok(usize::from(self.read_byte()?))
        } else if tag == tags.list_16 {
            Ok(self.read_int(2, false)? as usize)
        } else {
            Err(BinaryNodeError::InvalidListSizeTag(tag))
        }
    }

    fn read_jid_pair(&mut self) -> Result<String, BinaryNodeError> {
        let t1 = self.read_byte()?;
        let i = self.read_string(t1)?;
        let t2 = self.read_byte()?;
        let j = self.read_string(t2)?;
        if !j.is_empty() {
            Ok(format!("{}@{}", i, j))
        } else {
            Err(BinaryNodeError::InvalidJidPair(i, j))
        }
    }

    fn read_ad_jid(&mut self) -> Result<String, BinaryNodeError> {
        let domain_type = self.read_byte()?;
        let device = self.read_byte()?;
        let user_tag = self.read_byte()?;
        let user = self.read_string(user_tag)?;

        let server = if domain_type == WaJidDomains::Lid as u8 {
            JidServer::Lid
        } else if domain_type == WaJidDomains::Hosted as u8 {
            JidServer::Hosted
        } else if domain_type == WaJidDomains::HostedLid as u8 {
            JidServer::HostedLid
        } else {
            JidServer::SWhatsappNet
        };

        Ok(jid_encode(Some(&user), &server, Some(u32::from(device)), None))
    }

    fn read_fb_jid(&mut self) -> Result<String, BinaryNodeError> {
        let user_tag = self.read_byte()?;
        let user = self.read_string(user_tag)?;
        let device = self.read_int(2, false)?;
        let server_tag = self.read_byte()?;
        let server = self.read_string(server_tag)?;
        Ok(format!("{}:{}@{}", user, device, server))
    }

    fn read_interop_jid(&mut self) -> Result<String, BinaryNodeError> {
        let user_tag = self.read_byte()?;
        let user = self.read_string(user_tag)?;
        let device = self.read_int(2, false)?;
        let integrator = self.read_int(2, false)?;

        let before_server = *self.index;
        let server = match self.read_byte().and_then(|t| self.read_string(t)) {
            Ok(s) => s,
            Err(_) => {
                *self.index = before_server;
                "interop".to_string()
            }
        };

        Ok(format!("{}-{}:{}@{}", integrator, user, device, server))
    }

    fn get_token_double(&self, index1: usize, index2: usize) -> Result<String, BinaryNodeError> {
        let dict = self
            .opts
            .double_byte_tokens
            .get(index1)
            .ok_or(BinaryNodeError::InvalidDoubleTokenDict(index1))?;
        let value = dict
            .get(index2)
            .ok_or(BinaryNodeError::InvalidDoubleToken(index2))?;
        Ok((*value).to_string())
    }

    fn read_string(&mut self, tag: u8) -> Result<String, BinaryNodeError> {
        if tag >= 1 && usize::from(tag) < self.opts.single_byte_tokens.len() {
            return Ok(self.opts.single_byte_tokens[usize::from(tag)].to_string());
        }

        let tags = &self.opts.tags;
        if tag == tags.dictionary_0
            || tag == tags.dictionary_1
            || tag == tags.dictionary_2
            || tag == tags.dictionary_3
        {
            let index2 = usize::from(self.read_byte()?);
            self.get_token_double(usize::from(tag - tags.dictionary_0), index2)
        } else if tag == tags.list_empty {
            Ok(String::new())
        } else if tag == tags.binary_8 {
            let len = usize::from(self.read_byte()?);
            self.read_string_from_chars(len)
        } else if tag == tags.binary_20 {
            let len = self.read_int20()?;
            self.read_string_from_chars(len)
        } else if tag == tags.binary_32 {
            let len = self.read_int(4, false)? as usize;
            self.read_string_from_chars(len)
        } else if tag == tags.jid_pair {
            self.read_jid_pair()
        } else if tag == tags.fb_jid {
            self.read_fb_jid()
        } else if tag == tags.interop_jid {
            self.read_interop_jid()
        } else if tag == tags.ad_jid {
            self.read_ad_jid()
        } else if tag == tags.hex_8 || tag == tags.nibble_8 {
            self.read_packed8(tag)
        } else {
            Err(BinaryNodeError::InvalidStringTag(tag))
        }
    }

    fn read_list(&mut self, tag: u8) -> Result<Vec<BinaryNode>, BinaryNodeError> {
        let size = self.read_list_size(tag)?;
        let mut items = Vec::with_capacity(size);
        for _ in 0..size {
            items.push(self.read_node()?);
        }
        Ok(items)
    }

    fn read_node(&mut self) -> Result<BinaryNode, BinaryNodeError> {
        let list_tag = self.read_byte()?;
        let list_size = self.read_list_size(list_tag)?;
        let header_tag = self.read_byte()?;
        let header = self.read_string(header_tag)?;
        if list_size == 0 || header.is_empty() {
            return Err(BinaryNodeError::InvalidNode);
        }

        let mut attrs = BinaryNodeAttributes::new();
        let attributes_length = (list_size - 1) >> 1;
        for _ in 0..attributes_length {
            let key_tag = self.read_byte()?;
            let key = self.read_string(key_tag)?;
            let val_tag = self.read_byte()?;
            let value = self.read_string(val_tag)?;
            attrs.insert(key, value);
        }

        let content = if list_size % 2 == 0 {
            let tag = self.read_byte()?;
            if self.is_list_tag(tag) {
                Some(BinaryNodeData::List(self.read_list(tag)?))
            } else {
                let tags = &self.opts.tags;
                if tag == tags.binary_8 {
                    let len = usize::from(self.read_byte()?);
                    Some(BinaryNodeData::Bytes(self.read_bytes(len)?.to_vec()))
                } else if tag == tags.binary_20 {
                    let len = self.read_int20()?;
                    Some(BinaryNodeData::Bytes(self.read_bytes(len)?.to_vec()))
                } else if tag == tags.binary_32 {
                    let len = self.read_int(4, false)? as usize;
                    Some(BinaryNodeData::Bytes(self.read_bytes(len)?.to_vec()))
                } else {
                    Some(BinaryNodeData::String(self.read_string(tag)?))
                }
            }
        } else {
            None
        };

        Ok(BinaryNode {
            tag: header,
            attrs,
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wa_binary::constants::{DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS};
    use crate::wa_binary::encode::encode_binary_node;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_token_table_sizes() {
        assert_eq!(SINGLE_BYTE_TOKENS.len(), 236);
        assert_eq!(DOUBLE_BYTE_TOKENS.len(), 4);
        for dict in DOUBLE_BYTE_TOKENS {
            assert_eq!(dict.len(), 256);
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut attrs = BinaryNodeAttributes::new();
        attrs.insert("id".to_string(), "ABCDEF012345".to_string());
        attrs.insert("from".to_string(), "573001234567:4@s.whatsapp.net".to_string());
        attrs.insert("to".to_string(), "12036300012345-123@g.us".to_string());
        attrs.insert("timezone".to_string(), "America/Bogota".to_string());
        attrs.insert("t".to_string(), "1700000000".to_string());

        let child = BinaryNode {
            tag: "enc".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("type".to_string(), "pkmsg".to_string()),
                ("v".to_string(), "2".to_string()),
            ]),
            content: Some(BinaryNodeData::Bytes(vec![1, 2, 3, 4, 255])),
        };

        let node = BinaryNode {
            tag: "message".to_string(),
            attrs,
            content: Some(BinaryNodeData::List(vec![child])),
        };

        let encoded = encode_binary_node(&node).unwrap();
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn test_decode_zlib_compressed_node() {
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([("type".to_string(), "get".to_string())]),
            content: None,
        };
        let encoded = encode_binary_node(&node).unwrap();

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&encoded[1..]).unwrap();
        let mut compressed = vec![2u8];
        compressed.extend_from_slice(&encoder.finish().unwrap());

        let decoded = decode_binary_node(&compressed).unwrap();
        assert_eq!(decoded, node);
    }
}
