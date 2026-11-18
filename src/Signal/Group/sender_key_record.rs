use super::keyhelper::SigningKeyPair;
use super::sender_key_state::{SenderKeyState, SenderKeyStateStructure};
use serde::{Deserialize, Serialize};

const MAX_STATES: usize = 5;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyRecord {
    sender_key_states: Vec<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new() -> Self {
        Self {
            sender_key_states: Vec::new(),
        }
    }

    pub fn from_structures(structures: Vec<SenderKeyStateStructure>) -> Self {
        Self {
            sender_key_states: structures
                .into_iter()
                .map(SenderKeyState::from_structure)
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sender_key_states.is_empty()
    }

    pub fn get_sender_key_state(&self, key_id: Option<u32>) -> Option<&SenderKeyState> {
        match key_id {
            None => self.sender_key_states.last(),
            Some(id) => self
                .sender_key_states
                .iter()
                .find(|s| s.get_key_id() == id),
        }
    }

    pub fn get_sender_key_state_mut(&mut self, key_id: Option<u32>) -> Option<&mut SenderKeyState> {
        match key_id {
            None => self.sender_key_states.last_mut(),
            Some(id) => self
                .sender_key_states
                .iter_mut()
                .find(|s| s.get_key_id() == id),
        }
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signature_key: Vec<u8>,
    ) {
        self.sender_key_states.push(SenderKeyState::new_with_public_key(
            id,
            iteration,
            chain_key,
            signature_key,
        ));
        if self.sender_key_states.len() > MAX_STATES {
            self.sender_key_states.remove(0);
        }
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        key_pair: SigningKeyPair,
    ) {
        self.sender_key_states.clear();
        self.sender_key_states.push(SenderKeyState::new_with_key_pair(
            id,
            iteration,
            chain_key,
            key_pair,
        ));
    }

    pub fn serialize(&self) -> Vec<SenderKeyStateStructure> {
        self.sender_key_states
            .iter()
            .map(|s| s.get_structure().clone())
            .collect()
    }
}
