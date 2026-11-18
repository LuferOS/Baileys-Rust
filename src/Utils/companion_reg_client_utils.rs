use crate::utils::browser_utils::get_platform_id;

pub fn get_companion_platform_id(browser: &[String; 3]) -> String {
    get_platform_id(&browser[1])
}

pub fn build_pairing_qr_data(
    ref_token: &str,
    noise_key_b64: &str,
    identity_key_b64: &str,
    adv_b64: &str,
    _browser: &[String; 3],
) -> String {
    format!(
        "{},{},{},{}",
        ref_token, noise_key_b64, identity_key_b64, adv_b64
    )
}
