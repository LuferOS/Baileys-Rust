use crate::utils::crypto::{hkdf, CryptoError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: [u8; 16],
    cipher_key: [u8; 32],
    seed: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: Vec<u8>) -> Result<Self, CryptoError> {
        let derivative = hkdf(&seed, 64, Some(&[0u8; 32]), b"WhisperGroup")?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&derivative[0..16]);
        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&derivative[16..48]);

        Ok(Self {
            iteration,
            iv,
            cipher_key,
            seed,
        })
    }

    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    pub fn get_iv(&self) -> &[u8; 16] {
        &self.iv
    }

    pub fn get_cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    pub fn get_seed(&self) -> &[u8] {
        &self.seed
    }
}
