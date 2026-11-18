use super::ciphertext_message::{ints_to_byte_high_and_low, CURRENT_VERSION, SENDERKEY_TYPE};
use crate::utils::crypto::{CryptoError, Curve};
use prost::Message;
use thiserror::Error;

const SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, PartialEq, prost::Message)]
struct SenderKeyMessageProto {
    #[prost(uint32, optional, tag = "1")]
    id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    iteration: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum SenderKeyMessageError {
    #[error("invalid sender key message length")]
    InvalidLength,
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyMessage {
    message_version: u8,
    key_id: u32,
    iteration: u32,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    serialized: Vec<u8>,
}

impl SenderKeyMessage {
    pub fn new(
        key_id: u32,
        iteration: u32,
        ciphertext: Vec<u8>,
        signature_key: &[u8],
    ) -> Result<Self, SenderKeyMessageError> {
        let version = ints_to_byte_high_and_low(CURRENT_VERSION, CURRENT_VERSION);
        let proto_msg = SenderKeyMessageProto {
            id: Some(key_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.clone()),
        };
        let encoded = proto_msg.encode_to_vec();
        let mut to_sign = Vec::with_capacity(1 + encoded.len());
        to_sign.push(version);
        to_sign.extend_from_slice(&encoded);

        let signature = Curve::sign(signature_key, &to_sign)?;
        let mut serialized = Vec::with_capacity(to_sign.len() + signature.len());
        serialized.extend_from_slice(&to_sign);
        serialized.extend_from_slice(&signature);

        Ok(Self {
            message_version: CURRENT_VERSION,
            key_id,
            iteration,
            ciphertext,
            signature,
            serialized,
        })
    }

    pub fn from_serialized(serialized: &[u8]) -> Result<Self, SenderKeyMessageError> {
        if serialized.len() <= 1 + SIGNATURE_LENGTH {
            return Err(SenderKeyMessageError::InvalidLength);
        }
        let version = serialized[0];
        let msg_end = serialized.len() - SIGNATURE_LENGTH;
        let message_bytes = &serialized[1..msg_end];
        let signature = serialized[msg_end..].to_vec();

        let decoded = SenderKeyMessageProto::decode(message_bytes)?;
        let key_id = decoded
            .id
            .ok_or(SenderKeyMessageError::MissingField("id"))?;
        let iteration = decoded.iteration.unwrap_or(0);
        let ciphertext = decoded
            .ciphertext
            .ok_or(SenderKeyMessageError::MissingField("ciphertext"))?;

        Ok(Self {
            message_version: version >> 4,
            key_id,
            iteration,
            ciphertext,
            signature,
            serialized: serialized.to_vec(),
        })
    }

    pub fn get_key_id(&self) -> u32 {
        self.key_id
    }

    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    pub fn get_cipher_text(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn get_message_version(&self) -> u8 {
        self.message_version
    }

    pub fn verify_signature(&self, signature_key: &[u8]) -> Result<(), SenderKeyMessageError> {
        let split_idx = self.serialized.len() - SIGNATURE_LENGTH;
        let part1 = &self.serialized[..split_idx];
        let part2 = &self.serialized[split_idx..];
        if !Curve::verify(signature_key, part1, part2) {
            return Err(SenderKeyMessageError::InvalidSignature);
        }
        Ok(())
    }

    pub fn serialize(&self) -> &[u8] {
        &self.serialized
    }

    pub fn get_type(&self) -> u8 {
        SENDERKEY_TYPE
    }
}
