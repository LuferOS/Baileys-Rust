use super::sender_key_distribution_message::SenderKeyDistributionError;
use super::sender_key_message::{SenderKeyMessage, SenderKeyMessageError};
use super::sender_key_record::SenderKeyRecord;
use super::sender_key_state::SenderKeyState;
use super::sender_message_key::SenderMessageKey;
use crate::utils::crypto::{aes_decrypt_with_iv, aes_encrypt_with_iv, CryptoError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupCipherError {
    #[error("no session found to encrypt or decrypt group message")]
    NoSession,
    #[error("missing signing private key in sender key state")]
    MissingSigningPrivateKey,
    #[error("received message with old counter: current {current}, received {received}")]
    OldCounter { current: u32, received: u32 },
    #[error("over 2000 messages into the future")]
    CounterTooFarAhead,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("sender key message error: {0}")]
    SenderKeyMessage(#[from] SenderKeyMessageError),
    #[error("sender key distribution error: {0}")]
    SenderKeyDistribution(#[from] SenderKeyDistributionError),
}

pub struct GroupCipher;

impl GroupCipher {
    pub fn encrypt(
        record: &mut SenderKeyRecord,
        padded_plaintext: &[u8],
    ) -> Result<Vec<u8>, GroupCipherError> {
        let sender_key_state = record
            .get_sender_key_state_mut(None)
            .ok_or(GroupCipherError::NoSession)?;

        let iteration = sender_key_state.get_sender_chain_key().get_iteration();
        let target_iteration = if iteration == 0 { 0 } else { iteration + 1 };
        let sender_key = Self::get_sender_key(sender_key_state, target_iteration)?;

        let ciphertext = aes_encrypt_with_iv(
            padded_plaintext,
            sender_key.get_cipher_key(),
            sender_key.get_iv(),
        )?;

        let signing_private = sender_key_state
            .get_signing_key_private()
            .ok_or(GroupCipherError::MissingSigningPrivateKey)?;

        let sender_key_message = SenderKeyMessage::new(
            sender_key_state.get_key_id(),
            sender_key.get_iteration(),
            ciphertext,
            signing_private,
        )?;

        Ok(sender_key_message.serialize().to_vec())
    }

    pub fn decrypt(
        record: &mut SenderKeyRecord,
        sender_key_message_bytes: &[u8],
    ) -> Result<Vec<u8>, GroupCipherError> {
        let sender_key_message = SenderKeyMessage::from_serialized(sender_key_message_bytes)?;
        let sender_key_state = record
            .get_sender_key_state_mut(Some(sender_key_message.get_key_id()))
            .ok_or(GroupCipherError::NoSession)?;

        let signing_pub = sender_key_state.get_signing_key_public();
        sender_key_message.verify_signature(&signing_pub)?;

        let sender_key = Self::get_sender_key(sender_key_state, sender_key_message.get_iteration())?;
        let plaintext = aes_decrypt_with_iv(
            sender_key_message.get_cipher_text(),
            sender_key.get_cipher_key(),
            sender_key.get_iv(),
        )?;

        Ok(plaintext)
    }

    fn get_sender_key(
        sender_key_state: &mut SenderKeyState,
        iteration: u32,
    ) -> Result<SenderMessageKey, GroupCipherError> {
        let mut sender_chain_key = sender_key_state.get_sender_chain_key();
        if sender_chain_key.get_iteration() > iteration {
            if sender_key_state.has_sender_message_key(iteration) {
                if let Some(message_key) = sender_key_state.remove_sender_message_key(iteration)? {
                    return Ok(message_key);
                }
            }
            return Err(GroupCipherError::OldCounter {
                current: sender_chain_key.get_iteration(),
                received: iteration,
            });
        }

        if iteration.saturating_sub(sender_chain_key.get_iteration()) > 2000 {
            return Err(GroupCipherError::CounterTooFarAhead);
        }

        while sender_chain_key.get_iteration() < iteration {
            let msg_key = sender_chain_key.get_sender_message_key()?;
            sender_key_state.add_sender_message_key(&msg_key);
            sender_chain_key = sender_chain_key.get_next()?;
        }

        let next_chain = sender_chain_key.get_next()?;
        sender_key_state.set_sender_chain_key(&next_chain);
        Ok(sender_chain_key.get_sender_message_key()?)
    }
}
