use crate::defaults::{NOISE_MODE, WA_CERT_PUBLIC_KEY, WA_CERT_SERIAL};
use crate::proto::{cert_chain, handshake_message, CertChain};
use crate::types::KeyPair;
use crate::utils::crypto::{
    aes_decrypt_gcm, aes_encrypt_gcm, hkdf, sha256, CryptoError, Curve,
};
use crate::wa_binary::{decode_binary_node, BinaryNode, BinaryNodeError};
use prost::Message;
use thiserror::Error;

const IV_LENGTH: usize = 12;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("binary node decode error: {0}")]
    BinaryNode(#[from] BinaryNodeError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("missing server hello field: {0}")]
    MissingServerHelloField(&'static str),
    #[error("invalid noise leaf certificate")]
    InvalidLeafCertificate,
    #[error("invalid noise intermediate certificate")]
    InvalidIntermediateCertificate,
    #[error("noise certificate signature invalid")]
    InvalidLeafSignature,
    #[error("noise intermediate certificate signature invalid")]
    InvalidIntermediateSignature,
    #[error("certification issuer serial match failed")]
    InvalidIssuerSerial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseFrame {
    Raw(Vec<u8>),
    Node(BinaryNode),
}

fn generate_iv(counter: u32) -> [u8; IV_LENGTH] {
    let mut iv = [0u8; IV_LENGTH];
    iv[8..12].copy_from_slice(&counter.to_be_bytes());
    iv
}

struct TransportState {
    read_counter: u32,
    write_counter: u32,
    enc_key: Vec<u8>,
    dec_key: Vec<u8>,
}

impl TransportState {
    fn new(enc_key: Vec<u8>, dec_key: Vec<u8>) -> Self {
        Self {
            read_counter: 0,
            write_counter: 0,
            enc_key,
            dec_key,
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let iv = generate_iv(self.write_counter);
        self.write_counter = self.write_counter.wrapping_add(1);
        Ok(aes_encrypt_gcm(plaintext, &self.enc_key, &iv, &[])?)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let iv = generate_iv(self.read_counter);
        self.read_counter = self.read_counter.wrapping_add(1);
        Ok(aes_decrypt_gcm(ciphertext, &self.dec_key, &iv, &[])?)
    }
}

pub struct NoiseHandler {
    private_key: Vec<u8>,
    hash: Vec<u8>,
    salt: Vec<u8>,
    enc_key: Vec<u8>,
    dec_key: Vec<u8>,
    counter: u32,
    sent_intro: bool,
    intro_header: Vec<u8>,
    in_bytes: Vec<u8>,
    transport: Option<TransportState>,
}

impl NoiseHandler {
    pub fn new(key_pair: KeyPair, noise_header: &[u8], routing_info: Option<&[u8]>) -> Self {
        let hash = if NOISE_MODE.len() == 32 {
            NOISE_MODE.to_vec()
        } else {
            sha256(NOISE_MODE)
        };

        let intro_header = if let Some(info) = routing_info {
            let mut buf = Vec::with_capacity(7 + info.len() + noise_header.len());
            buf.extend_from_slice(b"ED");
            buf.push(0);
            buf.push(1);
            buf.push(((info.len() >> 16) & 0xff) as u8);
            buf.extend_from_slice(&((info.len() & 0xffff) as u16).to_be_bytes());
            buf.extend_from_slice(info);
            buf.extend_from_slice(noise_header);
            buf
        } else {
            noise_header.to_vec()
        };

        let mut handler = Self {
            private_key: key_pair.private,
            salt: hash.clone(),
            enc_key: hash.clone(),
            dec_key: hash.clone(),
            hash,
            counter: 0,
            sent_intro: false,
            intro_header,
            in_bytes: Vec::new(),
            transport: None,
        };

        handler.authenticate(noise_header);
        handler.authenticate(&key_pair.public);
        handler
    }

    pub fn authenticate(&mut self, data: &[u8]) {
        if self.transport.is_none() {
            let mut combined = Vec::with_capacity(self.hash.len() + data.len());
            combined.extend_from_slice(&self.hash);
            combined.extend_from_slice(data);
            self.hash = sha256(&combined);
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(transport) = &mut self.transport {
            return transport.encrypt(plaintext);
        }

        let iv = generate_iv(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let result = aes_encrypt_gcm(plaintext, &self.enc_key, &iv, &self.hash)?;
        self.authenticate(&result);
        Ok(result)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if let Some(transport) = &mut self.transport {
            return transport.decrypt(ciphertext);
        }

        let iv = generate_iv(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let result = aes_decrypt_gcm(ciphertext, &self.dec_key, &iv, &self.hash)?;
        self.authenticate(ciphertext);
        Ok(result)
    }

    fn local_hkdf(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), NoiseError> {
        let key = hkdf(data, 64, Some(&self.salt), b"")?;
        Ok((key[..32].to_vec(), key[32..64].to_vec()))
    }

    pub fn mix_into_key(&mut self, data: &[u8]) -> Result<(), NoiseError> {
        let (write, read) = self.local_hkdf(data)?;
        self.salt = write;
        self.enc_key = read.clone();
        self.dec_key = read;
        self.counter = 0;
        Ok(())
    }

    pub fn finish_init(&mut self) -> Result<(), NoiseError> {
        let (write, read) = self.local_hkdf(&[])?;
        self.transport = Some(TransportState::new(write, read));
        Ok(())
    }

    pub fn is_transport_ready(&self) -> bool {
        self.transport.is_some()
    }

    pub fn process_handshake(
        &mut self,
        server_hello: &handshake_message::ServerHello,
        noise_key: &KeyPair,
    ) -> Result<Vec<u8>, NoiseError> {
        let ephemeral = server_hello
            .ephemeral
            .as_deref()
            .ok_or(NoiseError::MissingServerHelloField("ephemeral"))?;
        let static_key = server_hello
            .r#static
            .as_deref()
            .ok_or(NoiseError::MissingServerHelloField("static"))?;
        let payload = server_hello
            .payload
            .as_deref()
            .ok_or(NoiseError::MissingServerHelloField("payload"))?;

        self.authenticate(ephemeral);
        let shared_ephemeral = Curve::shared_key(&self.private_key, ephemeral)?;
        self.mix_into_key(&shared_ephemeral)?;

        let dec_static_content = self.decrypt(static_key)?;
        let shared_static = Curve::shared_key(&self.private_key, &dec_static_content)?;
        self.mix_into_key(&shared_static)?;

        let cert_decoded = self.decrypt(payload)?;
        let cert_chain = CertChain::decode(cert_decoded.as_slice())?;

        let leaf = cert_chain.leaf.ok_or(NoiseError::InvalidLeafCertificate)?;
        let leaf_details = leaf
            .details
            .as_deref()
            .ok_or(NoiseError::InvalidLeafCertificate)?;
        let leaf_signature = leaf
            .signature
            .as_deref()
            .ok_or(NoiseError::InvalidLeafCertificate)?;

        let intermediate = cert_chain
            .intermediate
            .ok_or(NoiseError::InvalidIntermediateCertificate)?;
        let inter_details_bytes = intermediate
            .details
            .as_deref()
            .ok_or(NoiseError::InvalidIntermediateCertificate)?;
        let inter_signature = intermediate
            .signature
            .as_deref()
            .ok_or(NoiseError::InvalidIntermediateCertificate)?;

        let details = cert_chain::noise_certificate::Details::decode(inter_details_bytes)?;
        let details_key = details
            .key
            .as_deref()
            .ok_or(NoiseError::InvalidIntermediateCertificate)?;

        if !Curve::verify(details_key, leaf_details, leaf_signature) {
            return Err(NoiseError::InvalidLeafSignature);
        }

        if !Curve::verify(&WA_CERT_PUBLIC_KEY, inter_details_bytes, inter_signature) {
            return Err(NoiseError::InvalidIntermediateSignature);
        }

        if details.issuer_serial.map(|s| s as u64) != Some(WA_CERT_SERIAL as u64) {
            return Err(NoiseError::InvalidIssuerSerial);
        }

        let key_enc = self.encrypt(&noise_key.public)?;
        let shared_noise = Curve::shared_key(&noise_key.private, ephemeral)?;
        self.mix_into_key(&shared_noise)?;

        Ok(key_enc)
    }

    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let encrypted_storage;
        let payload = if let Some(transport) = &mut self.transport {
            encrypted_storage = transport.encrypt(data)?;
            encrypted_storage.as_slice()
        } else {
            data
        };

        let data_len = payload.len();
        let intro_size = if self.sent_intro {
            0
        } else {
            self.intro_header.len()
        };

        let mut frame = Vec::with_capacity(intro_size + 3 + data_len);
        if !self.sent_intro {
            frame.extend_from_slice(&self.intro_header);
            self.sent_intro = true;
        }

        frame.push(((data_len >> 16) & 0xff) as u8);
        frame.push(((data_len >> 8) & 0xff) as u8);
        frame.push((data_len & 0xff) as u8);
        frame.extend_from_slice(payload);

        Ok(frame)
    }

    pub fn decode_frame(&mut self, new_data: &[u8]) -> Result<Vec<NoiseFrame>, NoiseError> {
        self.in_bytes.extend_from_slice(new_data);
        let mut frames = Vec::new();

        while self.in_bytes.len() >= 3 {
            let size = ((self.in_bytes[0] as usize) << 16)
                | ((self.in_bytes[1] as usize) << 8)
                | (self.in_bytes[2] as usize);

            if self.in_bytes.len() < size + 3 {
                break;
            }

            let raw_frame = self.in_bytes[3..size + 3].to_vec();
            self.in_bytes.drain(..size + 3);

            if let Some(transport) = &mut self.transport {
                let decrypted = transport.decrypt(&raw_frame)?;
                let node = decode_binary_node(&decrypted)?;
                frames.push(NoiseFrame::Node(node));
            } else {
                frames.push(NoiseFrame::Raw(raw_frame));
            }
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::NOISE_WA_HEADER;
    use crate::wa_binary::{encode_binary_node, BinaryNodeAttributes};

    #[test]
    fn test_encode_frame_with_routing_info() {
        let kp = Curve::generate_key_pair();
        let routing = vec![0x08, 0x02, 0x08, 0x05];
        let mut handler = NoiseHandler::new(kp, &NOISE_WA_HEADER, Some(&routing));

        let frame1 = handler.encode_frame(b"hello").unwrap();
        assert_eq!(&frame1[0..2], b"ED");
        assert_eq!(&frame1[2..7], &[0, 1, 0, 0, 4]);
        assert_eq!(&frame1[7..11], routing.as_slice());
        assert_eq!(&frame1[11..15], &NOISE_WA_HEADER);
        assert_eq!(&frame1[15..18], &[0, 0, 5]);
        assert_eq!(&frame1[18..], b"hello");

        let frame2 = handler.encode_frame(b"ok").unwrap();
        assert_eq!(frame2, vec![0, 0, 2, b'o', b'k']);
    }

    #[test]
    fn test_chunked_raw_and_transport_frames() {
        let kp = Curve::generate_key_pair();
        let mut handler = NoiseHandler::new(kp, &NOISE_WA_HEADER, None);

        let raw_chunk = vec![0, 0, 3, 10, 20];
        assert!(handler.decode_frame(&raw_chunk).unwrap().is_empty());
        let frames = handler.decode_frame(&[30]).unwrap();
        assert_eq!(frames, vec![NoiseFrame::Raw(vec![10, 20, 30])]);

        // Verificar cifrado/descifrado en estado Transport (write/read invertidos como cliente-servidor)
        let key_a = vec![1u8; 32];
        let key_b = vec![2u8; 32];
        let mut client = NoiseHandler::new(Curve::generate_key_pair(), &NOISE_WA_HEADER, None);
        let mut server = NoiseHandler::new(Curve::generate_key_pair(), &NOISE_WA_HEADER, None);
        client.transport = Some(TransportState::new(key_a.clone(), key_b.clone()));
        server.transport = Some(TransportState::new(key_b, key_a));
        client.sent_intro = true;

        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([("type".to_string(), "get".to_string())]),
            content: None,
        };
        let encoded_node = encode_binary_node(&node).unwrap();
        let wire = client.encode_frame(&encoded_node).unwrap();
        let decoded = server.decode_frame(&wire).unwrap();
        assert_eq!(decoded, vec![NoiseFrame::Node(node)]);
    }
}
