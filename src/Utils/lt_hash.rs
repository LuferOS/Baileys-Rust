use crate::utils::crypto::{hkdf, CryptoError};

const LT_HASH_SIZE: usize = 128;
const LT_HASH_INFO: &[u8] = b"WhatsApp Patch Integrity";

#[derive(Debug, Clone, Copy, Default)]
pub struct LtHashAntiTampering;

impl LtHashAntiTampering {
    pub const fn new() -> Self {
        Self
    }

    pub fn add<T: AsRef<[u8]>>(&self, base: &[u8], items: &[T]) -> Result<Vec<u8>, CryptoError> {
        let mut output = Self::normalize_base(base);
        for item in items {
            let derived = hkdf(item.as_ref(), LT_HASH_SIZE, None, LT_HASH_INFO)?;
            Self::perform_pointwise(&mut output, &derived, true);
        }
        Ok(output)
    }

    pub fn subtract<T: AsRef<[u8]>>(
        &self,
        base: &[u8],
        items: &[T],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut output = Self::normalize_base(base);
        for item in items {
            let derived = hkdf(item.as_ref(), LT_HASH_SIZE, None, LT_HASH_INFO)?;
            Self::perform_pointwise(&mut output, &derived, false);
        }
        Ok(output)
    }

    pub fn subtract_then_add<S: AsRef<[u8]>, A: AsRef<[u8]>>(
        &self,
        base: &[u8],
        subtract: &[S],
        add: &[A],
    ) -> Result<Vec<u8>, CryptoError> {
        let after_sub = self.subtract(base, subtract)?;
        self.add(&after_sub, add)
    }

    fn normalize_base(base: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; LT_HASH_SIZE];
        let copy_len = base.len().min(LT_HASH_SIZE);
        out[..copy_len].copy_from_slice(&base[..copy_len]);
        out
    }

    fn perform_pointwise(acc: &mut [u8], rhs: &[u8], add: bool) {
        for i in (0..LT_HASH_SIZE).step_by(2) {
            let a = u16::from_le_bytes([acc[i], acc[i + 1]]);
            let b = u16::from_le_bytes([rhs[i], rhs[i + 1]]);
            let res = if add {
                a.wrapping_add(b)
            } else {
                a.wrapping_sub(b)
            };
            let bytes = res.to_le_bytes();
            acc[i] = bytes[0];
            acc[i + 1] = bytes[1];
        }
    }
}

pub const LT_HASH_ANTI_TAMPERING: LtHashAntiTampering = LtHashAntiTampering::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lt_hash_commutative_and_reversible() {
        let base = vec![0u8; 128];
        let item_a = b"mutation-a";
        let item_b = b"mutation-b";
        let item_c = b"mutation-c";

        let ab = LT_HASH_ANTI_TAMPERING
            .add(&base, &[item_a.as_slice(), item_b.as_slice()])
            .unwrap();
        let ba = LT_HASH_ANTI_TAMPERING
            .add(&base, &[item_b.as_slice(), item_a.as_slice()])
            .unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 128);

        let replaced = LT_HASH_ANTI_TAMPERING
            .subtract_then_add(&ab, &[item_a.as_slice()], &[item_c.as_slice()])
            .unwrap();
        let direct = LT_HASH_ANTI_TAMPERING
            .add(&base, &[item_b.as_slice(), item_c.as_slice()])
            .unwrap();
        assert_eq!(replaced, direct);

        let back = LT_HASH_ANTI_TAMPERING
            .subtract(&direct, &[item_b.as_slice(), item_c.as_slice()])
            .unwrap();
        assert_eq!(back, base);
    }
}
