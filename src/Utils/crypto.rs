use crate::types::{KeyPair, SignedKeyPair};
use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher,
};
use curve25519_dalek::{
    edwards::EdwardsPoint,
    montgomery::MontgomeryPoint,
    scalar::{clamp_integer, Scalar},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub const KEY_BUNDLE_TYPE: [u8; 1] = [5];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacVariant {
    Sha256,
    Sha512,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid iv length")]
    InvalidIvLength,
    #[error("invalid input length")]
    InvalidInputLength,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("hkdf expansion failed")]
    HkdfFailed,
}

pub fn generate_signal_pub_key(pub_key: &[u8]) -> Vec<u8> {
    if pub_key.len() == 33 {
        pub_key.to_vec()
    } else {
        let mut out = Vec::with_capacity(1 + pub_key.len());
        out.extend_from_slice(&KEY_BUNDLE_TYPE);
        out.extend_from_slice(pub_key);
        out
    }
}

fn strip_signal_pub_key(pub_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    let raw = if pub_key.len() == 33 && pub_key[0] == KEY_BUNDLE_TYPE[0] {
        &pub_key[1..]
    } else if pub_key.len() == 32 {
        pub_key
    } else {
        return Err(CryptoError::InvalidKeyLength);
    };
    raw.try_into().map_err(|_| CryptoError::InvalidKeyLength)
}

pub struct Curve;

impl Curve {
    pub fn generate_key_pair() -> KeyPair {
        let mut raw_priv = [0u8; 32];
        OsRng.fill_bytes(&mut raw_priv);
        let clamped_priv = clamp_integer(raw_priv);
        let secret = StaticSecret::from(clamped_priv);
        let public = PublicKey::from(&secret);
        KeyPair {
            private: clamped_priv.to_vec(),
            public: public.to_bytes().to_vec(),
        }
    }

    pub fn shared_key(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let priv_arr: [u8; 32] = private_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let pub_arr = strip_signal_pub_key(public_key)?;
        let secret = StaticSecret::from(priv_arr);
        let public = PublicKey::from(pub_arr);
        Ok(secret.diffie_hellman(&public).to_bytes().to_vec())
    }

    pub fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let priv_arr: [u8; 32] = private_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let clamped = clamp_integer(priv_arr);
        let mut scalar = Scalar::from_bytes_mod_order(clamped);

        let e_point = EdwardsPoint::mul_base(&scalar);
        let mut a_bytes = e_point.compress().to_bytes();
        if (a_bytes[31] & 0x80) != 0 {
            scalar = -scalar;
            a_bytes[31] &= 0x7f;
        }

        let mut random = [0u8; 64];
        OsRng.fill_bytes(&mut random);

        let mut prefix = [0xffu8; 32];
        prefix[0] = 0xfe;

        let mut h1 = Sha512::new();
        h1.update(prefix);
        h1.update(scalar.as_bytes());
        h1.update(message);
        h1.update(random);
        let r = Scalar::from_bytes_mod_order_wide(&h1.finalize().into());

        let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();

        let mut h2 = Sha512::new();
        h2.update(r_bytes);
        h2.update(a_bytes);
        h2.update(message);
        let h = Scalar::from_bytes_mod_order_wide(&h2.finalize().into());

        let s = r + h * scalar;

        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&r_bytes);
        sig.extend_from_slice(s.as_bytes());
        Ok(sig)
    }

    pub fn verify(pub_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let Ok(u_arr) = strip_signal_pub_key(pub_key) else {
            return false;
        };

        let sign_bit = (signature[63] & 0x80) >> 7;
        let Some(a_point) = MontgomeryPoint(u_arr).to_edwards(sign_bit) else {
            return false;
        };
        let a_bytes = a_point.compress().to_bytes();

        let Ok(r_bytes): Result<[u8; 32], _> = signature[0..32].try_into() else {
            return false;
        };
        let Ok(mut s_bytes): Result<[u8; 32], _> = signature[32..64].try_into() else {
            return false;
        };
        s_bytes[31] &= 0x7f;

        let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
            return false;
        };

        let mut h_hasher = Sha512::new();
        h_hasher.update(r_bytes);
        h_hasher.update(a_bytes);
        h_hasher.update(message);
        let h = Scalar::from_bytes_mod_order_wide(&h_hasher.finalize().into());

        let check_r = EdwardsPoint::mul_base(&s) - (a_point * h);
        check_r.compress().to_bytes() == r_bytes
    }
}

pub fn signed_key_pair(
    identity_key_pair: &KeyPair,
    key_id: u32,
) -> Result<SignedKeyPair, CryptoError> {
    let pre_key = Curve::generate_key_pair();
    let pub_key = generate_signal_pub_key(&pre_key.public);
    let signature = Curve::sign(&identity_key_pair.private, &pub_key)?;
    Ok(SignedKeyPair {
        key_pair: pre_key,
        signature,
        key_id,
    })
}

pub fn aes_encrypt_gcm(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != 12 {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn aes_decrypt_gcm(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != 12 {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn aes_encrypt_ctr(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut cipher =
        Aes256Ctr::new_from_slice(key, iv).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut out = plaintext.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

pub fn aes_decrypt_ctr(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes_encrypt_ctr(ciphertext, key, iv)
}

pub fn aes_decrypt_with_iv(
    buffer: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256CbcDec::new_from_slice(key, iv).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(buffer)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn aes_decrypt(buffer: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if buffer.len() < 16 {
        return Err(CryptoError::InvalidInputLength);
    }
    aes_decrypt_with_iv(&buffer[16..], key, &buffer[..16])
}

pub fn aes_encrypt_with_iv(
    buffer: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256CbcEnc::new_from_slice(key, iv).map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(buffer))
}

pub fn aes_encrypt(buffer: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let enc = aes_encrypt_with_iv(buffer, key, &iv)?;
    let mut out = Vec::with_capacity(16 + enc.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&enc);
    Ok(out)
}

pub fn hmac_sign(
    buffer: &[u8],
    key: &[u8],
    variant: HmacVariant,
) -> Result<Vec<u8>, CryptoError> {
    match variant {
        HmacVariant::Sha256 => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            mac.update(buffer);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HmacVariant::Sha512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            mac.update(buffer);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

pub fn sha256(buffer: &[u8]) -> Vec<u8> {
    Sha256::digest(buffer).to_vec()
}

pub fn md5(buffer: &[u8]) -> Vec<u8> {
    Md5::digest(buffer).to_vec()
}

pub fn hkdf(
    buffer: &[u8],
    expanded_length: usize,
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, buffer);
    let mut okm = vec![0u8; expanded_length];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(okm)
}

pub fn derive_pairing_code_key(pairing_code: &str, salt: &[u8]) -> Vec<u8> {
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pairing_code.as_bytes(), salt, 2 << 16, &mut derived);
    derived.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_dh_and_xeddsa() {
        let alice = Curve::generate_key_pair();
        let bob = Curve::generate_key_pair();

        let shared_a = Curve::shared_key(&alice.private, &bob.public).unwrap();
        let shared_b = Curve::shared_key(&bob.private, &alice.public).unwrap();
        assert_eq!(shared_a, shared_b);

        let signed = signed_key_pair(&alice, 1).unwrap();
        let pub_with_prefix = generate_signal_pub_key(&signed.key_pair.public);
        assert!(Curve::verify(&alice.public, &pub_with_prefix, &signed.signature));
        assert!(!Curve::verify(&bob.public, &pub_with_prefix, &signed.signature));
    }

    #[test]
    fn test_aes_modes() {
        let key = [7u8; 32];
        let iv_gcm = [3u8; 12];
        let iv_16 = [9u8; 16];
        let msg = b"baileys-rust-protocol";
        let aad = b"noise-aad";

        let gcm_enc = aes_encrypt_gcm(msg, &key, &iv_gcm, aad).unwrap();
        let gcm_dec = aes_decrypt_gcm(&gcm_enc, &key, &iv_gcm, aad).unwrap();
        assert_eq!(gcm_dec, msg);

        let ctr_enc = aes_encrypt_ctr(msg, &key, &iv_16).unwrap();
        let ctr_dec = aes_decrypt_ctr(&ctr_enc, &key, &iv_16).unwrap();
        assert_eq!(ctr_dec, msg);

        let cbc_enc = aes_encrypt(msg, &key).unwrap();
        let cbc_dec = aes_decrypt(&cbc_enc, &key).unwrap();
        assert_eq!(cbc_dec, msg);
    }

    #[test]
    fn test_kdf_and_hashes() {
        let okm = hkdf(b"input", 64, Some(b"salt"), b"info").unwrap();
        assert_eq!(okm.len(), 64);

        let derived = derive_pairing_code_key("ABCDEFGH", b"1234567890123456");
        assert_eq!(derived.len(), 32);

        assert_eq!(sha256(b"abc").len(), 32);
        assert_eq!(md5(b"abc").len(), 16);
        assert_eq!(hmac_sign(b"abc", b"key", HmacVariant::Sha256).unwrap().len(), 32);
        assert_eq!(hmac_sign(b"abc", b"key", HmacVariant::Sha512).unwrap().len(), 64);
    }
}
