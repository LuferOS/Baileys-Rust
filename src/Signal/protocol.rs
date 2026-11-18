use crate::types::{E2ESession, KeyPair, MessageCipherType};
use crate::utils::crypto::{
    aes_decrypt_with_iv, aes_encrypt_with_iv, generate_signal_pub_key, hkdf, hmac_sign,
    CryptoError, Curve, HmacVariant,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const SIGNAL_VERSION_BYTE: u8 = 0x33;
const MAX_SKIPPED_MESSAGE_KEYS: usize = 2000;
const MAX_PREVIOUS_SESSIONS: usize = 40;
const MAX_RECEIVING_CHAINS: usize = 5;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("invalid signed prekey signature")]
    InvalidSignature,
    #[error("invalid whisper message format")]
    InvalidMessageFormat,
    #[error("invalid message version: {0}")]
    InvalidVersion(u8),
    #[error("mac verification failed")]
    InvalidMac,
    #[error("no open session")]
    NoOpenSession,
    #[error("message counter too far ahead")]
    CounterTooFarAhead,
    #[error("missing message key for counter {0}")]
    MissingMessageKey(u32),
    #[error("missing prekey field: {0}")]
    MissingField(&'static str),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignalMessageProto {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ratchet_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub previous_counter: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PreKeySignalMessageProto {
    #[prost(uint32, optional, tag = "5")]
    pub registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "1")]
    pub pre_key_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub signed_pre_key_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub base_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub identity_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPreKey {
    pub pre_key_id: Option<u32>,
    pub signed_key_id: u32,
    pub base_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    pub chain_key: Vec<u8>,
    pub counter: u32,
    pub message_keys: BTreeMap<u32, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivingChainEntry {
    pub ratchet_key: Vec<u8>,
    pub chain: ChainState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub registration_id: u32,
    pub local_registration_id: u32,
    pub remote_identity_key: Vec<u8>,
    pub local_identity_key: Vec<u8>,
    pub base_key: Vec<u8>,
    pub root_key: Vec<u8>,
    pub sending_ratchet_key: KeyPair,
    pub sending_chain: Option<ChainState>,
    pub receiving_chains: Vec<ReceivingChainEntry>,
    pub previous_counter: u32,
    pub pending_pre_key: Option<PendingPreKey>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub current_session: Option<SessionState>,
    pub previous_sessions: Vec<SessionState>,
}

struct DerivedMessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
}

fn derive_message_keys(seed: &[u8]) -> Result<DerivedMessageKeys, ProtocolError> {
    let okm = hkdf(seed, 80, Some(&[0u8; 32]), b"WhisperMessageKeys")?;
    Ok(DerivedMessageKeys {
        cipher_key: okm[0..32].try_into().unwrap(),
        mac_key: okm[32..64].try_into().unwrap(),
        iv: okm[64..80].try_into().unwrap(),
    })
}

fn advance_chain_key(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let msg_key_seed = hmac_sign(&[0x01], chain_key, HmacVariant::Sha256)?;
    let next_chain_key = hmac_sign(&[0x02], chain_key, HmacVariant::Sha256)?;
    Ok((msg_key_seed, next_chain_key))
}

fn compute_whisper_mac(
    sender_identity: &[u8],
    receiver_identity: &[u8],
    mac_key: &[u8],
    serialized: &[u8],
) -> Result<[u8; 8], ProtocolError> {
    let mut input =
        Vec::with_capacity(sender_identity.len() + receiver_identity.len() + serialized.len());
    input.extend_from_slice(sender_identity);
    input.extend_from_slice(receiver_identity);
    input.extend_from_slice(serialized);
    let mac = hmac_sign(&input, mac_key, HmacVariant::Sha256)?;
    let mut truncated = [0u8; 8];
    truncated.copy_from_slice(&mac[..8]);
    Ok(truncated)
}

impl SessionState {
    pub fn init_outgoing(
        our_identity_key: &KeyPair,
        local_registration_id: u32,
        bundle: &E2ESession,
    ) -> Result<Self, ProtocolError> {
        if !Curve::verify(
            &bundle.identity_key,
            &bundle.signed_pre_key.public_key,
            &bundle.signed_pre_key.signature,
        ) {
            return Err(ProtocolError::InvalidSignature);
        }

        let our_base_key = Curve::generate_key_pair();
        let dh1 = Curve::shared_key(&our_identity_key.private, &bundle.signed_pre_key.public_key)?;
        let dh2 = Curve::shared_key(&our_base_key.private, &bundle.identity_key)?;
        let dh3 = Curve::shared_key(&our_base_key.private, &bundle.signed_pre_key.public_key)?;

        let mut master_secret = Vec::with_capacity(32 * 5);
        master_secret.extend_from_slice(&[0xffu8; 32]);
        master_secret.extend_from_slice(&dh1);
        master_secret.extend_from_slice(&dh2);
        master_secret.extend_from_slice(&dh3);
        if let Some(pre_key) = &bundle.pre_key {
            let dh4 = Curve::shared_key(&our_base_key.private, &pre_key.public_key)?;
            master_secret.extend_from_slice(&dh4);
        }

        let derived = hkdf(&master_secret, 64, Some(&[0u8; 32]), b"WhisperText")?;
        let sending_ratchet_key = Curve::generate_key_pair();
        let dh_ratchet = Curve::shared_key(
            &sending_ratchet_key.private,
            &bundle.signed_pre_key.public_key,
        )?;
        let ratchet_derived = hkdf(&dh_ratchet, 64, Some(&derived[0..32]), b"WhisperRatchet")?;

        let base_key_pub = generate_signal_pub_key(&our_base_key.public);

        Ok(Self {
            registration_id: bundle.registration_id,
            local_registration_id,
            remote_identity_key: generate_signal_pub_key(&bundle.identity_key),
            local_identity_key: generate_signal_pub_key(&our_identity_key.public),
            base_key: base_key_pub.clone(),
            root_key: ratchet_derived[0..32].to_vec(),
            sending_ratchet_key,
            sending_chain: Some(ChainState {
                chain_key: ratchet_derived[32..64].to_vec(),
                counter: 0,
                message_keys: BTreeMap::new(),
            }),
            receiving_chains: Vec::new(),
            previous_counter: 0,
            pending_pre_key: Some(PendingPreKey {
                pre_key_id: bundle.pre_key.as_ref().map(|p| p.key_id),
                signed_key_id: bundle.signed_pre_key.key_id,
                base_key: base_key_pub,
            }),
        })
    }

    pub fn init_incoming(
        our_identity_key: &KeyPair,
        local_registration_id: u32,
        our_signed_pre_key: &KeyPair,
        our_pre_key: Option<&KeyPair>,
        pkmsg: &PreKeySignalMessageProto,
    ) -> Result<Self, ProtocolError> {
        let their_identity = pkmsg
            .identity_key
            .as_deref()
            .ok_or(ProtocolError::MissingField("identity_key"))?;
        let their_base_key = pkmsg
            .base_key
            .as_deref()
            .ok_or(ProtocolError::MissingField("base_key"))?;

        let dh1 = Curve::shared_key(&our_signed_pre_key.private, their_identity)?;
        let dh2 = Curve::shared_key(&our_identity_key.private, their_base_key)?;
        let dh3 = Curve::shared_key(&our_signed_pre_key.private, their_base_key)?;

        let mut master_secret = Vec::with_capacity(32 * 5);
        master_secret.extend_from_slice(&[0xffu8; 32]);
        master_secret.extend_from_slice(&dh1);
        master_secret.extend_from_slice(&dh2);
        master_secret.extend_from_slice(&dh3);
        if let Some(pre_key) = our_pre_key {
            let dh4 = Curve::shared_key(&pre_key.private, their_base_key)?;
            master_secret.extend_from_slice(&dh4);
        }

        let derived = hkdf(&master_secret, 64, Some(&[0u8; 32]), b"WhisperText")?;

        Ok(Self {
            registration_id: pkmsg.registration_id.unwrap_or(0),
            local_registration_id,
            remote_identity_key: generate_signal_pub_key(their_identity),
            local_identity_key: generate_signal_pub_key(&our_identity_key.public),
            base_key: generate_signal_pub_key(their_base_key),
            root_key: derived[0..32].to_vec(),
            sending_ratchet_key: our_signed_pre_key.clone(),
            sending_chain: None,
            receiving_chains: Vec::new(),
            previous_counter: 0,
            pending_pre_key: None,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageCipherType, Vec<u8>), ProtocolError> {
        let chain = self
            .sending_chain
            .as_mut()
            .ok_or(ProtocolError::NoOpenSession)?;
        let counter = chain.counter;
        let (msg_key_seed, next_chain_key) = advance_chain_key(&chain.chain_key)?;
        chain.chain_key = next_chain_key;
        chain.counter = counter.saturating_add(1);

        let keys = derive_message_keys(&msg_key_seed)?;
        let ciphertext = aes_encrypt_with_iv(plaintext, &keys.cipher_key, &keys.iv)?;

        let signal_proto = SignalMessageProto {
            ratchet_key: Some(generate_signal_pub_key(&self.sending_ratchet_key.public)),
            counter: Some(counter),
            previous_counter: Some(self.previous_counter),
            ciphertext: Some(ciphertext),
        };

        let proto_bytes = signal_proto.encode_to_vec();
        let mut whisper_msg = Vec::with_capacity(1 + proto_bytes.len() + 8);
        whisper_msg.push(SIGNAL_VERSION_BYTE);
        whisper_msg.extend_from_slice(&proto_bytes);

        let mac = compute_whisper_mac(
            &self.local_identity_key,
            &self.remote_identity_key,
            &keys.mac_key,
            &whisper_msg,
        )?;
        whisper_msg.extend_from_slice(&mac);

        if let Some(pending) = &self.pending_pre_key {
            let pk_proto = PreKeySignalMessageProto {
                registration_id: Some(self.local_registration_id),
                pre_key_id: pending.pre_key_id,
                signed_pre_key_id: Some(pending.signed_key_id),
                base_key: Some(pending.base_key.clone()),
                identity_key: Some(self.local_identity_key.clone()),
                message: Some(whisper_msg),
            };
            let pk_bytes = pk_proto.encode_to_vec();
            let mut out = Vec::with_capacity(1 + pk_bytes.len());
            out.push(SIGNAL_VERSION_BYTE);
            out.extend_from_slice(&pk_bytes);
            Ok((MessageCipherType::Pkmsg, out))
        } else {
            Ok((MessageCipherType::Msg, whisper_msg))
        }
    }

    pub fn decrypt_whisper_message(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if bytes.len() < 10 {
            return Err(ProtocolError::InvalidMessageFormat);
        }
        let version = bytes[0];
        if (version & 0x0f) != 3 {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let mac_start = bytes.len() - 8;
        let msg_part = &bytes[..mac_start];
        let provided_mac = &bytes[mac_start..];
        let proto_msg = SignalMessageProto::decode(&bytes[1..mac_start])?;

        let their_ratchet = proto_msg
            .ratchet_key
            .as_deref()
            .ok_or(ProtocolError::MissingField("ratchet_key"))?;
        let their_ratchet_33 = generate_signal_pub_key(their_ratchet);
        let counter = proto_msg.counter.unwrap_or(0);
        let ciphertext = proto_msg
            .ciphertext
            .as_deref()
            .ok_or(ProtocolError::MissingField("ciphertext"))?;

        let chain_idx = if let Some(idx) = self
            .receiving_chains
            .iter()
            .position(|c| c.ratchet_key == their_ratchet_33)
        {
            idx
        } else {
            self.previous_counter = self.sending_chain.as_ref().map(|c| c.counter).unwrap_or(0);

            let dh_recv = Curve::shared_key(&self.sending_ratchet_key.private, &their_ratchet_33)?;
            let recv_step = hkdf(&dh_recv, 64, Some(&self.root_key), b"WhisperRatchet")?;

            let new_ratchet_key = Curve::generate_key_pair();
            let dh_send = Curve::shared_key(&new_ratchet_key.private, &their_ratchet_33)?;
            let send_step = hkdf(&dh_send, 64, Some(&recv_step[0..32]), b"WhisperRatchet")?;

            self.root_key = send_step[0..32].to_vec();
            self.sending_ratchet_key = new_ratchet_key;
            self.sending_chain = Some(ChainState {
                chain_key: send_step[32..64].to_vec(),
                counter: 0,
                message_keys: BTreeMap::new(),
            });

            self.receiving_chains.push(ReceivingChainEntry {
                ratchet_key: their_ratchet_33,
                chain: ChainState {
                    chain_key: recv_step[32..64].to_vec(),
                    counter: 0,
                    message_keys: BTreeMap::new(),
                },
            });
            if self.receiving_chains.len() > MAX_RECEIVING_CHAINS {
                self.receiving_chains.remove(0);
            }
            self.receiving_chains.len() - 1
        };

        let chain = &mut self.receiving_chains[chain_idx].chain;
        let msg_key_seed = if counter < chain.counter {
            chain
                .message_keys
                .get(&counter)
                .cloned()
                .ok_or(ProtocolError::MissingMessageKey(counter))?
        } else {
            let diff = (counter - chain.counter) as usize;
            if diff > MAX_SKIPPED_MESSAGE_KEYS {
                return Err(ProtocolError::CounterTooFarAhead);
            }
            let mut temp_chain = chain.chain_key.clone();
            let mut temp_counter = chain.counter;
            let mut skipped = Vec::new();

            while temp_counter < counter {
                let (seed, next_key) = advance_chain_key(&temp_chain)?;
                skipped.push((temp_counter, seed));
                temp_chain = next_key;
                temp_counter += 1;
            }
            let (seed, next_key) = advance_chain_key(&temp_chain)?;

            let keys = derive_message_keys(&seed)?;
            let expected_mac = compute_whisper_mac(
                &self.remote_identity_key,
                &self.local_identity_key,
                &keys.mac_key,
                msg_part,
            )?;
            if expected_mac.as_slice() != provided_mac {
                return Err(ProtocolError::InvalidMac);
            }
            let plaintext = aes_decrypt_with_iv(ciphertext, &keys.cipher_key, &keys.iv)?;

            for (k, v) in skipped {
                chain.message_keys.insert(k, v);
            }
            while chain.message_keys.len() > MAX_SKIPPED_MESSAGE_KEYS {
                if let Some(&first_k) = chain.message_keys.keys().next() {
                    chain.message_keys.remove(&first_k);
                }
            }
            chain.chain_key = next_key;
            chain.counter = counter + 1;
            self.pending_pre_key = None;
            return Ok(plaintext);
        };

        let keys = derive_message_keys(&msg_key_seed)?;
        let expected_mac = compute_whisper_mac(
            &self.remote_identity_key,
            &self.local_identity_key,
            &keys.mac_key,
            msg_part,
        )?;
        if expected_mac.as_slice() != provided_mac {
            return Err(ProtocolError::InvalidMac);
        }
        let plaintext = aes_decrypt_with_iv(ciphertext, &keys.cipher_key, &keys.iv)?;
        chain.message_keys.remove(&counter);
        self.pending_pre_key = None;
        Ok(plaintext)
    }
}

impl SessionRecord {
    pub fn have_open_session(&self) -> bool {
        self.current_session.is_some()
    }

    pub fn promote_state(&mut self, state: SessionState) {
        if let Some(prev) = self.current_session.replace(state) {
            self.previous_sessions.insert(0, prev);
            if self.previous_sessions.len() > MAX_PREVIOUS_SESSIONS {
                self.previous_sessions.truncate(MAX_PREVIOUS_SESSIONS);
            }
        }
    }

    pub fn has_session_with_base_key(&self, base_key: &[u8]) -> bool {
        if let Some(cur) = &self.current_session {
            if cur.base_key == base_key {
                return true;
            }
        }
        self.previous_sessions.iter().any(|s| s.base_key == base_key)
    }

    pub fn decrypt_whisper_message(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if let Some(cur) = &mut self.current_session {
            let mut trial = cur.clone();
            if let Ok(plain) = trial.decrypt_whisper_message(bytes) {
                *cur = trial;
                return Ok(plain);
            }
        }

        for idx in 0..self.previous_sessions.len() {
            let mut trial = self.previous_sessions[idx].clone();
            if let Ok(plain) = trial.decrypt_whisper_message(bytes) {
                self.previous_sessions[idx] = trial;
                return Ok(plain);
            }
        }

        Err(ProtocolError::NoOpenSession)
    }
}

pub fn decode_pre_key_signal_message(bytes: &[u8]) -> Result<PreKeySignalMessageProto, ProtocolError> {
    if bytes.len() < 2 {
        return Err(ProtocolError::InvalidMessageFormat);
    }
    let version = bytes[0];
    if (version & 0x0f) != 3 {
        return Err(ProtocolError::InvalidVersion(version));
    }
    Ok(PreKeySignalMessageProto::decode(&bytes[1..])?)
}
