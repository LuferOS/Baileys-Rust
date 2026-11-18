use crate::utils::crypto::{generate_signal_pub_key, Curve};
use rand::{rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub fn generate_sender_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn generate_sender_key_id() -> u32 {
    OsRng.gen_range(0..2_147_483_647)
}

pub fn generate_sender_signing_key() -> SigningKeyPair {
    let kp = Curve::generate_key_pair();
    SigningKeyPair {
        public: generate_signal_pub_key(&kp.public),
        private: kp.private,
    }
}
