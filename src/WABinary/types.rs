use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
