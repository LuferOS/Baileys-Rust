use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub key_id: u32,
}
