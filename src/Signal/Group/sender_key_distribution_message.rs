use super::ciphertext_message::{
    ints_to_byte_high_and_low, CURRENT_VERSION, SENDERKEY_DISTRIBUTION_TYPE,
};
use prost::Message;
use thiserror::Error;

#[derive(Clone, PartialEq, prost::Message)]
struct SenderKeyDistributionMessageProto {
    #[prost(uint32, optional, tag = "1")]
    id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    iteration: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    chain_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    signing_key: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum SenderKeyDistributionError {
    #[error("empty serialized sender key distribution message")]
    EmptyMessage,
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyDistributionMessage {
    id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    signature_key: Vec<u8>,
    serialized: Vec<u8>,
}

impl SenderKeyDistributionMessage {
    pub fn new(id: u32, iteration: u32, chain_key: Vec<u8>, signature_key: Vec<u8>) -> Self {
        let version = ints_to_byte_high_and_low(CURRENT_VERSION, CURRENT_VERSION);
        let proto_msg = SenderKeyDistributionMessageProto {
            id: Some(id),
            iteration: Some(iteration),
            chain_key: Some(chain_key.clone()),
            signing_key: Some(signature_key.clone()),
        };
        let encoded = proto_msg.encode_to_vec();
        let mut serialized = Vec::with_capacity(1 + encoded.len());
        serialized.push(version);
        serialized.extend_from_slice(&encoded);

        Self {
            id,
            iteration,
            chain_key,
            signature_key,
            serialized,
        }
    }

    pub fn from_serialized(serialized: &[u8]) -> Result<Self, SenderKeyDistributionError> {
        if serialized.len() < 2 {
            return Err(SenderKeyDistributionError::EmptyMessage);
        }
        let decoded = SenderKeyDistributionMessageProto::decode(&serialized[1..])?;
        let id = decoded
            .id
            .ok_or(SenderKeyDistributionError::MissingField("id"))?;
        let iteration = decoded.iteration.unwrap_or(0);
        let chain_key = decoded
            .chain_key
            .ok_or(SenderKeyDistributionError::MissingField("chain_key"))?;
        let signature_key = decoded
            .signing_key
            .ok_or(SenderKeyDistributionError::MissingField("signing_key"))?;

        Ok(Self {
            id,
            iteration,
            chain_key,
            signature_key,
            serialized: serialized.to_vec(),
        })
    }

    pub fn serialize(&self) -> &[u8] {
        &self.serialized
    }

    pub fn get_type(&self) -> u8 {
        SENDERKEY_DISTRIBUTION_TYPE
    }

    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    pub fn get_chain_key(&self) -> &[u8] {
        &self.chain_key
    }

    pub fn get_signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }
}
