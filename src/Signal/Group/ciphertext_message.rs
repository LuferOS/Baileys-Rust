pub const UNSUPPORTED_VERSION: u8 = 1;
pub const CURRENT_VERSION: u8 = 3;
pub const WHISPER_TYPE: u8 = 2;
pub const PREKEY_TYPE: u8 = 3;
pub const SENDERKEY_TYPE: u8 = 4;
pub const SENDERKEY_DISTRIBUTION_TYPE: u8 = 5;
pub const ENCRYPTED_MESSAGE_OVERHEAD: usize = 53;

pub fn ints_to_byte_high_and_low(high_value: u8, low_value: u8) -> u8 {
    (high_value << 4) | (low_value & 0x0f)
}
