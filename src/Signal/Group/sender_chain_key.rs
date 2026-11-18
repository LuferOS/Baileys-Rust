use super::sender_message_key::SenderMessageKey;
use crate::utils::crypto::{hmac_sign, CryptoError, HmacVariant};

const MESSAGE_KEY_SEED: [u8; 1] = [0x01];
const CHAIN_KEY_SEED: [u8; 1] = [0x02];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: Vec<u8>,
}

impl SenderChainKey {
    pub fn new(iteration: u32, chain_key: Vec<u8>) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    pub fn get_sender_message_key(&self) -> Result<SenderMessageKey, CryptoError> {
        let derived = hmac_sign(&MESSAGE_KEY_SEED, &self.chain_key, HmacVariant::Sha256)?;
        SenderMessageKey::new(self.iteration, derived)
    }

    pub fn get_next(&self) -> Result<Self, CryptoError> {
        let next_key = hmac_sign(&CHAIN_KEY_SEED, &self.chain_key, HmacVariant::Sha256)?;
        Ok(Self {
            iteration: self.iteration.saturating_add(1),
            chain_key: next_key,
        })
    }

    pub fn get_seed(&self) -> &[u8] {
        &self.chain_key
    }
}
