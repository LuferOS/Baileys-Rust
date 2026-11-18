use super::keyhelper::SigningKeyPair;
use super::sender_chain_key::SenderChainKey;
use super::sender_message_key::SenderMessageKey;
use crate::utils::crypto::CryptoError;
use serde::{Deserialize, Serialize};

const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderChainKeyStructure {
    pub iteration: u32,
    pub seed: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderSigningKeyStructure {
    pub public: Vec<u8>,
    pub private: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderMessageKeyStructure {
    pub iteration: u32,
    pub seed: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyStateStructure {
    pub sender_key_id: u32,
    pub sender_chain_key: SenderChainKeyStructure,
    pub sender_signing_key: SenderSigningKeyStructure,
    pub sender_message_keys: Vec<SenderMessageKeyStructure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyState {
    structure: SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new_with_key_pair(
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key_pair: SigningKeyPair,
    ) -> Self {
        Self {
            structure: SenderKeyStateStructure {
                sender_key_id: id,
                sender_chain_key: SenderChainKeyStructure {
                    iteration,
                    seed: chain_key,
                },
                sender_signing_key: SenderSigningKeyStructure {
                    public: signature_key_pair.public,
                    private: Some(signature_key_pair.private),
                },
                sender_message_keys: Vec::new(),
            },
        }
    }

    pub fn new_with_public_key(
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key_public: Vec<u8>,
    ) -> Self {
        Self {
            structure: SenderKeyStateStructure {
                sender_key_id: id,
                sender_chain_key: SenderChainKeyStructure {
                    iteration,
                    seed: chain_key,
                },
                sender_signing_key: SenderSigningKeyStructure {
                    public: signature_key_public,
                    private: None,
                },
                sender_message_keys: Vec::new(),
            },
        }
    }

    pub fn from_structure(structure: SenderKeyStateStructure) -> Self {
        Self { structure }
    }

    pub fn get_key_id(&self) -> u32 {
        self.structure.sender_key_id
    }

    pub fn get_sender_chain_key(&self) -> SenderChainKey {
        SenderChainKey::new(
            self.structure.sender_chain_key.iteration,
            self.structure.sender_chain_key.seed.clone(),
        )
    }

    pub fn set_sender_chain_key(&mut self, chain_key: &SenderChainKey) {
        self.structure.sender_chain_key = SenderChainKeyStructure {
            iteration: chain_key.get_iteration(),
            seed: chain_key.get_seed().to_vec(),
        };
    }

    pub fn get_signing_key_public(&self) -> Vec<u8> {
        let pub_key = &self.structure.sender_signing_key.public;
        if pub_key.len() == 32 {
            let mut fixed = Vec::with_capacity(33);
            fixed.push(0x05);
            fixed.extend_from_slice(pub_key);
            fixed
        } else {
            pub_key.clone()
        }
    }

    pub fn get_signing_key_private(&self) -> Option<&[u8]> {
        self.structure
            .sender_signing_key
            .private
            .as_deref()
            .filter(|k| !k.is_empty())
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> bool {
        self.structure
            .sender_message_keys
            .iter()
            .any(|k| k.iteration == iteration)
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) {
        self.structure
            .sender_message_keys
            .push(SenderMessageKeyStructure {
                iteration: sender_message_key.get_iteration(),
                seed: sender_message_key.get_seed().to_vec(),
            });

        if self.structure.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            self.structure.sender_message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>, CryptoError> {
        if let Some(idx) = self
            .structure
            .sender_message_keys
            .iter()
            .position(|k| k.iteration == iteration)
        {
            let entry = self.structure.sender_message_keys.remove(idx);
            return Ok(Some(SenderMessageKey::new(entry.iteration, entry.seed)?));
        }
        Ok(None)
    }

    pub fn get_structure(&self) -> &SenderKeyStateStructure {
        &self.structure
    }
}
