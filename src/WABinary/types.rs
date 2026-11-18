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
    pub list_8: u8,
    pub list_16: u8,
    pub jid_pair: u8,
    pub hex_8: u8,
    pub binary_8: u8,
    pub binary_20: u8,
    pub binary_32: u8,
    pub nibble_8: u8,
    pub ad_jid: u8,
    pub packed_max: u8,
}

#[derive(Debug, Clone)]
pub struct BinaryNodeCodingOptions {
    pub tags: Tags,
    pub token_map: HashMap<String, TokenIndex>,
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
}
