use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub type BinaryNodeAttributes = HashMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryNodeData {
    List(Vec<BinaryNode>),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryNode {
    pub tag: String,
    pub attrs: BinaryNodeAttributes,
    pub content: Option<BinaryNodeData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenIndex {
    pub dict: Option<u8>,
    pub index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tags {
    pub list_empty: u8,
    pub dictionary_0: u8,
    pub dictionary_1: u8,
    pub dictionary_2: u8,
    pub dictionary_3: u8,
    pub interop_jid: u8,
    pub fb_jid: u8,
    pub ad_jid: u8,
    pub list_8: u8,
    pub list_16: u8,
    pub jid_pair: u8,
    pub hex_8: u8,
    pub binary_8: u8,
    pub binary_20: u8,
    pub binary_32: u8,
    pub nibble_8: u8,
    pub packed_max: u8,
}

#[derive(Debug, Clone)]
pub struct BinaryNodeCodingOptions {
    pub tags: Tags,
    pub single_byte_tokens: &'static [&'static str],
    pub double_byte_tokens: &'static [&'static [&'static str]],
    pub token_map: HashMap<&'static str, TokenIndex>,
}

#[derive(Debug, Error)]
pub enum BinaryNodeError {
    #[error("{text}")]
    NodeError { text: String, code: Option<i32> },
    #[error("invalid node: tag cannot be empty")]
    EmptyTag,
    #[error("string too large to encode: {0}")]
    StringTooLarge(usize),
    #[error("too many bytes to pack")]
    TooManyPackedBytes,
    #[error("invalid byte for nibble: {0}")]
    InvalidNibbleByte(u8),
    #[error("invalid hex byte: {0}")]
    InvalidHexByte(u8),
    #[error("end of stream")]
    EndOfStream,
    #[error("invalid hex value: {0}")]
    InvalidHexValue(u8),
    #[error("invalid nibble value: {0}")]
    InvalidNibbleValue(u8),
    #[error("unknown packed tag: {0}")]
    UnknownPackedTag(u8),
    #[error("invalid tag for list size: {0}")]
    InvalidListSizeTag(u8),
    #[error("invalid jid pair: {0}, {1}")]
    InvalidJidPair(String, String),
    #[error("invalid string with tag: {0}")]
    InvalidStringTag(u8),
    #[error("invalid double token dict ({0})")]
    InvalidDoubleTokenDict(usize),
    #[error("invalid double token ({0})")]
    InvalidDoubleToken(usize),
    #[error("invalid node")]
    InvalidNode,
    #[error("decompression error: {0}")]
    Decompression(#[from] std::io::Error),
}
