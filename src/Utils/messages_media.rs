use crate::defaults::{MediaType, DEFAULT_ORIGIN};
use crate::proto::media_retry_notification::ResultType as MediaRetryResultType;
use crate::proto::message::{
    AudioMessage, DocumentMessage, ImageMessage, StickerMessage, VideoMessage,
};
use crate::proto::{MediaRetryNotification, Message, ServerErrorReceipt};
use crate::socket::messages_send::{MessagesSendError, MessagesSocket};
use crate::types::WaMessageKey;
use crate::utils::crypto::{
    aes_decrypt_gcm, aes_decrypt_with_iv, aes_encrypt_gcm, aes_encrypt_with_iv, hkdf, hmac_sign,
    sha256, CryptoError, HmacVariant,
};
use crate::utils::generics::generate_message_id_v2;
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_child_buffer, jid_normalized_user, BinaryNode,
    BinaryNodeAttributes, BinaryNodeData,
};
use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use prost::Message as ProstMessage;
use rand::{rngs::OsRng, RngCore};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, ORIGIN, RANGE};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::fs;
use tokio::process::Command;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub const DEF_MEDIA_HOST: &str = "mmg.whatsapp.net";
const PLACEHOLDER_MEDIA_HOST: &str = "a.whatsapp.net";
const AES_CHUNK_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("cannot derive from empty media key")]
    EmptyMediaKey,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http status error: {0}")]
    HttpStatus(u16),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("messages send error: {0}")]
    MessagesSend(#[from] MessagesSendError),
    #[error("no valid media URL or directPath present in message")]
    MissingMediaUrl,
    #[error("invalid encrypted media buffer length")]
    InvalidEncryptedLength,
    #[error("media mac verification failed")]
    InvalidMac,
    #[error("media upload failed on all hosts")]
    UploadFailedAllHosts,
    #[error("missing media path for media type")]
    MissingMediaPath,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid data url")]
    InvalidDataUrl,
    #[error("ffmpeg failed: {0}")]
    FfmpegFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDecryptionKeyInfo {
    pub iv: [u8; 16],
    pub cipher_key: [u8; 32],
    pub mac_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub enum WaMediaUpload {
    Bytes(Vec<u8>),
    File(PathBuf),
    Url(String),
}

#[derive(Debug, Clone)]
pub struct RawMediaUploadData {
    pub file_path: PathBuf,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
}

#[derive(Debug, Clone)]
pub struct EncryptedMediaBytes {
    pub media_key: Vec<u8>,
    pub encrypted: Vec<u8>,
    pub mac: [u8; 10],
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
}

#[derive(Debug, Clone)]
pub struct EncryptedMediaResult {
    pub media_key: Vec<u8>,
    pub original_file_path: Option<PathBuf>,
    pub enc_file_path: PathBuf,
    pub mac: [u8; 10],
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DownloadableMessage {
    pub media_key: Option<Vec<u8>>,
    pub direct_path: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MediaDownloadOptions {
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMediaUploadResult {
    pub url: Option<String>,
    pub direct_path: Option<String>,
    pub meta_hmac: Option<String>,
    pub ts: Option<u64>,
    pub fbid: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaUploadResponse {
    pub media_url: String,
    pub direct_path: String,
    pub meta_hmac: Option<String>,
    pub ts: Option<u64>,
    pub fbid: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRetryEncrypted {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRetryEvent {
    pub key: WaMessageKey,
    pub media: Option<MediaRetryEncrypted>,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
}

pub fn hkdf_info_key(media_type: MediaType) -> String {
    format!("WhatsApp {} Keys", media_type.hkdf_key())
}

pub fn get_media_keys(
    buffer: &[u8],
    media_type: MediaType,
) -> Result<MediaDecryptionKeyInfo, MediaError> {
    if buffer.is_empty() {
        return Err(MediaError::EmptyMediaKey);
    }
    let info = hkdf_info_key(media_type);
    let expanded = hkdf(buffer, 112, None, info.as_bytes())?;
    let mut iv = [0u8; 16];
    let mut cipher_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    iv.copy_from_slice(&expanded[0..16]);
    cipher_key.copy_from_slice(&expanded[16..48]);
    mac_key.copy_from_slice(&expanded[48..80]);

    Ok(MediaDecryptionKeyInfo {
        iv,
        cipher_key,
        mac_key,
    })
}

pub fn get_media_keys_from_base64(
    b64: &str,
    media_type: MediaType,
) -> Result<MediaDecryptionKeyInfo, MediaError> {
    let clean = b64.replace("data:;base64,", "");
    let bytes = BASE64.decode(clean)?;
    get_media_keys(&bytes, media_type)
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let unreserved = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~';
        if unreserved {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

pub fn encode_base64_encoded_string_for_upload(b64: &str) -> String {
    let url_safe = b64
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string();
    percent_encode(&url_safe)
}

pub fn get_url_from_direct_path(direct_path: &str, host: Option<&str>) -> String {
    let resolved_host = host.unwrap_or(DEF_MEDIA_HOST);
    format!("https://{}{}", resolved_host, direct_path)
}

pub fn extract_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split('?').next()?;
    if host.is_empty() || host == PLACEHOLDER_MEDIA_HOST {
        return None;
    }
    Some(host.to_string())
}

fn build_http_client(_timeout_ms: Option<u64>) -> Result<reqwest::Client, MediaError> {
    static SHARED_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(client) = SHARED_CLIENT.get() {
        return Ok(client.clone());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .tcp_keepalive(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(16)
        .http2_adaptive_window(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let _ = SHARED_CLIENT.set(client.clone());
    Ok(client)
}

pub async fn read_media_upload_bytes(
    media: &WaMediaUpload,
    headers: Option<&HashMap<String, String>>,
    timeout_ms: Option<u64>,
) -> Result<Vec<u8>, MediaError> {
    match media {
        WaMediaUpload::Bytes(b) => Ok(b.clone()),
        WaMediaUpload::File(path) => Ok(fs::read(path).await?),
        WaMediaUpload::Url(url_str) => {
            if let Some(rest) = url_str.strip_prefix("data:") {
                let (_, b64_part) = rest.split_once(',').ok_or(MediaError::InvalidDataUrl)?;
                return Ok(BASE64.decode(b64_part)?);
            }
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                let client = build_http_client(timeout_ms)?;
                let mut req = client.get(url_str);
                if let Some(hdrs) = headers {
                    for (k, v) in hdrs {
                        req = req.header(k.as_str(), v.as_str());
                    }
                }
                let resp = req.send().await?;
                if !resp.status().is_success() {
                    return Err(MediaError::HttpStatus(resp.status().as_u16()));
                }
                return Ok(resp.bytes().await?.to_vec());
            }
            Ok(fs::read(url_str).await?)
        }
    }
}

pub async fn get_raw_media_upload_data(
    media: &WaMediaUpload,
    media_type: MediaType,
) -> Result<RawMediaUploadData, MediaError> {
    let data = read_media_upload_bytes(media, None, None).await?;
    let file_length = data.len() as u64;
    let file_sha256 = sha256(&data);
    let file_path = std::env::temp_dir().join(format!(
        "{:?}{}",
        media_type,
        generate_message_id_v2(None)
    ));
    fs::write(&file_path, &data).await?;

    Ok(RawMediaUploadData {
        file_path,
        file_sha256,
        file_length,
    })
}

pub fn encrypt_media_bytes(
    plaintext: &[u8],
    media_type: MediaType,
) -> Result<EncryptedMediaBytes, MediaError> {
    let mut media_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut media_key);
    let keys = get_media_keys(&media_key, media_type)?;

    let file_sha256 = sha256(plaintext);
    let cipher_bytes = aes_encrypt_with_iv(plaintext, &keys.cipher_key, &keys.iv)?;

    let mut mac_input = Vec::with_capacity(keys.iv.len() + cipher_bytes.len());
    mac_input.extend_from_slice(&keys.iv);
    mac_input.extend_from_slice(&cipher_bytes);
    let full_mac = hmac_sign(&mac_input, &keys.mac_key, HmacVariant::Sha256)?;
    let mut mac = [0u8; 10];
    mac.copy_from_slice(&full_mac[..10]);

    let mut encrypted = Vec::with_capacity(cipher_bytes.len() + 10);
    encrypted.extend_from_slice(&cipher_bytes);
    encrypted.extend_from_slice(&mac);

    let file_enc_sha256 = sha256(&encrypted);

    Ok(EncryptedMediaBytes {
        media_key,
        encrypted,
        mac,
        file_enc_sha256,
        file_sha256,
        file_length: plaintext.len() as u64,
    })
}

pub async fn encrypted_stream(
    media: &WaMediaUpload,
    media_type: MediaType,
    save_original_file_if_required: bool,
) -> Result<EncryptedMediaResult, MediaError> {
    let plaintext = read_media_upload_bytes(media, None, None).await?;
    let enc = encrypt_media_bytes(&plaintext, media_type)?;

    let tmp_dir = std::env::temp_dir();
    let enc_file_path = tmp_dir.join(format!(
        "{:?}{}-enc",
        media_type,
        generate_message_id_v2(None)
    ));
    fs::write(&enc_file_path, &enc.encrypted).await?;

    let original_file_path = if save_original_file_if_required {
        let orig_path = tmp_dir.join(format!(
            "{:?}{}-original",
            media_type,
            generate_message_id_v2(None)
        ));
        fs::write(&orig_path, &plaintext).await?;
        Some(orig_path)
    } else {
        None
    };

    Ok(EncryptedMediaResult {
        media_key: enc.media_key,
        original_file_path,
        enc_file_path,
        mac: enc.mac,
        file_enc_sha256: enc.file_enc_sha256,
        file_sha256: enc.file_sha256,
        file_length: enc.file_length,
    })
}

pub fn decrypt_media_bytes(
    encrypted_with_mac: &[u8],
    media_key: &[u8],
    media_type: MediaType,
) -> Result<Vec<u8>, MediaError> {
    if encrypted_with_mac.len() <= 10 {
        return Err(MediaError::InvalidEncryptedLength);
    }
    let keys = get_media_keys(media_key, media_type)?;
    let split_idx = encrypted_with_mac.len() - 10;
    let ciphertext = &encrypted_with_mac[..split_idx];
    let provided_mac = &encrypted_with_mac[split_idx..];

    let mut mac_input = Vec::with_capacity(keys.iv.len() + ciphertext.len());
    mac_input.extend_from_slice(&keys.iv);
    mac_input.extend_from_slice(ciphertext);
    let expected_mac = hmac_sign(&mac_input, &keys.mac_key, HmacVariant::Sha256)?;
    if &expected_mac[..10] != provided_mac {
        return Err(MediaError::InvalidMac);
    }

    Ok(aes_decrypt_with_iv(ciphertext, &keys.cipher_key, &keys.iv)?)
}

fn to_smallest_chunk_size(num: usize) -> usize {
    (num / AES_CHUNK_SIZE) * AES_CHUNK_SIZE
}

pub async fn download_content_from_message(
    msg: &DownloadableMessage,
    media_type: MediaType,
    opts: &MediaDownloadOptions,
) -> Result<Vec<u8>, MediaError> {
    let fallback_host = opts
        .host
        .as_deref()
        .map(String::from)
        .or_else(|| msg.url.as_deref().and_then(extract_host));

    let download_url = if let Some(ref dp) = msg.direct_path {
        get_url_from_direct_path(dp, fallback_host.as_deref())
    } else if let Some(ref u) = msg.url {
        u.clone()
    } else {
        return Err(MediaError::MissingMediaUrl);
    };

    let media_key = msg.media_key.as_deref().ok_or(MediaError::EmptyMediaKey)?;
    let keys = get_media_keys(media_key, media_type)?;

    download_encrypted_content(&download_url, &keys, opts).await
}

pub async fn download_encrypted_content(
    download_url: &str,
    keys: &MediaDecryptionKeyInfo,
    opts: &MediaDownloadOptions,
) -> Result<Vec<u8>, MediaError> {
    let mut start_chunk = 0usize;
    let mut bytes_fetched = 0usize;
    let mut first_block_is_iv = false;

    if let Some(sb) = opts.start_byte {
        if sb > 0 {
            let chunk = to_smallest_chunk_size(sb);
            if chunk > 0 {
                start_chunk = chunk - AES_CHUNK_SIZE;
                bytes_fetched = chunk;
                first_block_is_iv = true;
            }
        }
    }

    let end_chunk = opts
        .end_byte
        .map(|eb| to_smallest_chunk_size(eb) + AES_CHUNK_SIZE);

    let mut header_map = HeaderMap::new();
    for (k, v) in &opts.headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            header_map.insert(name, val);
        }
    }
    header_map.insert(ORIGIN, HeaderValue::from_static(DEFAULT_ORIGIN));

    if start_chunk > 0 || end_chunk.is_some() {
        let range_val = match end_chunk {
            Some(ec) => format!("bytes={}-{}", start_chunk, ec),
            None => format!("bytes={}-", start_chunk),
        };
        if let Ok(hv) = HeaderValue::from_str(&range_val) {
            header_map.insert(RANGE, hv);
        }
    }

    let client = build_http_client(opts.timeout_ms)?;
    let resp = client.get(download_url).headers(header_map).send().await?;
    if !resp.status().is_success() {
        return Err(MediaError::HttpStatus(resp.status().as_u16()));
    }
    let raw = resp.bytes().await?;

    let decrypt_len = to_smallest_chunk_size(raw.len());
    let mut data = &raw[..decrypt_len];

    let iv_value: &[u8] = if first_block_is_iv {
        if data.len() < AES_CHUNK_SIZE {
            return Err(MediaError::InvalidEncryptedLength);
        }
        let iv_slice = &data[..AES_CHUNK_SIZE];
        data = &data[AES_CHUNK_SIZE..];
        iv_slice
    } else {
        &keys.iv
    };

    let decrypted = if opts.end_byte.is_some() {
        let cipher = Aes256CbcDec::new_from_slices(&keys.cipher_key, iv_value)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<NoPadding>(data)
            .map_err(|_| CryptoError::DecryptionFailed)?
    } else {
        aes_decrypt_with_iv(data, &keys.cipher_key, iv_value)?
    };

    if opts.start_byte.is_some() || opts.end_byte.is_some() {
        let start = match opts.start_byte {
            Some(sb) if bytes_fetched < sb => (sb - bytes_fetched).min(decrypted.len()),
            _ => 0,
        };
        let end = match opts.end_byte {
            Some(eb) if bytes_fetched + decrypted.len() >= eb => {
                eb.saturating_sub(bytes_fetched).min(decrypted.len())
            }
            _ => decrypted.len(),
        };
        return Ok(decrypted[start..end].to_vec());
    }

    Ok(decrypted)
}

pub async fn upload_media_to_server(
    file_path: &Path,
    media_type: MediaType,
    file_enc_sha256_b64: &str,
    messages_socket: &MessagesSocket,
    custom_upload_hosts: &[String],
    custom_headers: &HashMap<String, String>,
    timeout_ms: Option<u64>,
) -> Result<MediaUploadResponse, MediaError> {
    let media_path = media_type.path().ok_or(MediaError::MissingMediaPath)?;
    let mut upload_info = messages_socket.refresh_media_conn(false).await?;

    let mut hosts: Vec<String> = custom_upload_hosts.to_vec();
    for h in &upload_info.hosts {
        hosts.push(h.hostname.clone());
    }

    let encoded_token = encode_base64_encoded_string_for_upload(file_enc_sha256_b64);
    let file_bytes = fs::read(file_path).await?;
    let client = build_http_client(timeout_ms)?;

    let mut header_map = HeaderMap::new();
    for (k, v) in custom_headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            header_map.insert(name, val);
        }
    }
    header_map.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    header_map.insert(ORIGIN, HeaderValue::from_static(DEFAULT_ORIGIN));

    for hostname in hosts {
        let auth_encoded = percent_encode(&upload_info.auth);
        let url = format!(
            "https://{}{}/{}?auth={}&token={}",
            hostname, media_path, encoded_token, auth_encoded, encoded_token
        );

        let resp = client
            .post(&url)
            .headers(header_map.clone())
            .body(file_bytes.clone())
            .send()
            .await;

        if let Ok(r) = resp {
            if let Ok(parsed) = r.json::<RawMediaUploadResult>().await {
                if parsed.url.is_some() || parsed.direct_path.is_some() {
                    return Ok(MediaUploadResponse {
                        media_url: parsed.url.unwrap_or_default(),
                        direct_path: parsed.direct_path.unwrap_or_default(),
                        meta_hmac: parsed.meta_hmac,
                        ts: parsed.ts,
                        fbid: parsed.fbid,
                    });
                }
            }
        }

        if let Ok(refreshed) = messages_socket.refresh_media_conn(true).await {
            upload_info = refreshed;
        }
    }

    Err(MediaError::UploadFailedAllHosts)
}

pub async fn extract_video_thumb(
    path: &Path,
    dest_path: &Path,
    time: &str,
    width: u32,
) -> Result<(), MediaError> {
    let status = Command::new("ffmpeg")
        .arg("-ss")
        .arg(time)
        .arg("-i")
        .arg(path)
        .arg("-y")
        .arg("-vf")
        .arg(format!("scale={}:-1", width))
        .arg("-vframes")
        .arg("1")
        .arg("-f")
        .arg("image2")
        .arg(dest_path)
        .status()
        .await?;

    if !status.success() {
        return Err(MediaError::FfmpegFailed(format!("exit status {}", status)));
    }
    Ok(())
}

pub fn media_message_sha256_b64(message: &Message) -> Option<String> {
    let sha = if let Some(ref m) = message.image_message {
        let inner: &ImageMessage = Borrow::borrow(m);
        inner.file_sha256.as_deref()
    } else if let Some(ref m) = message.video_message {
        let inner: &VideoMessage = Borrow::borrow(m);
        inner.file_sha256.as_deref()
    } else if let Some(ref m) = message.audio_message {
        let inner: &AudioMessage = Borrow::borrow(m);
        inner.file_sha256.as_deref()
    } else if let Some(ref m) = message.document_message {
        let inner: &DocumentMessage = Borrow::borrow(m);
        inner.file_sha256.as_deref()
    } else if let Some(ref m) = message.sticker_message {
        let inner: &StickerMessage = Borrow::borrow(m);
        inner.file_sha256.as_deref()
    } else {
        None
    }?;
    Some(BASE64.encode(sha))
}

pub fn extension_for_media_message(message: &Message) -> Option<String> {
    if message.location_message.is_some()
        || message.live_location_message.is_some()
        || message.product_message.is_some()
    {
        return Some(".jpeg".to_string());
    }

    let mimetype = if let Some(ref m) = message.image_message {
        let inner: &ImageMessage = Borrow::borrow(m);
        inner.mimetype.as_deref()
    } else if let Some(ref m) = message.video_message {
        let inner: &VideoMessage = Borrow::borrow(m);
        inner.mimetype.as_deref()
    } else if let Some(ref m) = message.audio_message {
        let inner: &AudioMessage = Borrow::borrow(m);
        inner.mimetype.as_deref()
    } else if let Some(ref m) = message.document_message {
        let inner: &DocumentMessage = Borrow::borrow(m);
        inner.mimetype.as_deref()
    } else if let Some(ref m) = message.sticker_message {
        let inner: &StickerMessage = Borrow::borrow(m);
        inner.mimetype.as_deref()
    } else {
        None
    }?;

    mimetype
        .split(';')
        .next()
        .and_then(|base| base.split('/').nth(1))
        .map(String::from)
}

fn get_media_retry_key(media_key: &[u8]) -> Result<Vec<u8>, MediaError> {
    Ok(hkdf(
        media_key,
        32,
        None,
        b"WhatsApp Media Retry Notification",
    )?)
}

pub fn encrypt_media_retry_request(
    key: &WaMessageKey,
    media_key: &[u8],
    me_id: &str,
) -> Result<BinaryNode, MediaError> {
    let msg_id = key
        .id
        .as_deref()
        .ok_or(MediaError::MissingField("key.id"))?;
    let remote_jid = key
        .remote_jid
        .as_deref()
        .ok_or(MediaError::MissingField("key.remote_jid"))?;

    let recp = ServerErrorReceipt {
        stanza_id: Some(msg_id.to_string()),
    };
    let recp_buffer = recp.encode_to_vec();

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let retry_key = get_media_retry_key(media_key)?;
    let ciphertext = aes_encrypt_gcm(&recp_buffer, &retry_key, &iv, msg_id.as_bytes())?;

    let mut rmr_attrs = BinaryNodeAttributes::from([
        ("jid".to_string(), remote_jid.to_string()),
        (
            "from_me".to_string(),
            (key.from_me == Some(true)).to_string(),
        ),
    ]);
    if let Some(ref participant) = key.participant {
        rmr_attrs.insert("participant".to_string(), participant.clone());
    }

    Ok(BinaryNode {
        tag: "receipt".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("id".to_string(), msg_id.to_string()),
            ("to".to_string(), jid_normalized_user(Some(me_id))),
            ("type".to_string(), "server-error".to_string()),
        ]),
        content: Some(BinaryNodeData::List(vec![
            BinaryNode {
                tag: "encrypt".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "enc_p".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(ciphertext)),
                    },
                    BinaryNode {
                        tag: "enc_iv".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(iv.to_vec())),
                    },
                ])),
            },
            BinaryNode {
                tag: "rmr".to_string(),
                attrs: rmr_attrs,
                content: None,
            },
        ])),
    })
}

pub fn get_status_code_for_media_retry(code: i32) -> Option<u16> {
    if code == MediaRetryResultType::Success as i32 {
        Some(200)
    } else if code == MediaRetryResultType::DecryptionError as i32 {
        Some(412)
    } else if code == MediaRetryResultType::NotFound as i32 {
        Some(404)
    } else if code == MediaRetryResultType::GeneralError as i32 {
        Some(418)
    } else {
        None
    }
}

pub fn decode_media_retry_node(node: &BinaryNode) -> Result<MediaRetryEvent, MediaError> {
    let rmr_node =
        get_binary_node_child(Some(node), "rmr").ok_or(MediaError::MissingField("rmr"))?;

    let key = WaMessageKey {
        id: node.attrs.get("id").cloned(),
        remote_jid: rmr_node.attrs.get("jid").cloned(),
        from_me: Some(rmr_node.attrs.get("from_me").map(|s| s.as_str()) == Some("true")),
        participant: rmr_node.attrs.get("participant").cloned(),
        ..Default::default()
    };

    if let Some(error_node) = get_binary_node_child(Some(node), "error") {
        let code = error_node
            .attrs
            .get("code")
            .and_then(|c| c.parse::<i32>().ok())
            .unwrap_or(0);
        return Ok(MediaRetryEvent {
            key,
            media: None,
            error_code: get_status_code_for_media_retry(code),
            error_message: Some(format!("Failed to re-upload media ({})", code)),
        });
    }

    let encrypted_info = get_binary_node_child(Some(node), "encrypt");
    let ciphertext = get_binary_node_child_buffer(encrypted_info, "enc_p");
    let iv = get_binary_node_child_buffer(encrypted_info, "enc_iv");

    if let (Some(ct), Some(iv_bytes)) = (ciphertext, iv) {
        Ok(MediaRetryEvent {
            key,
            media: Some(MediaRetryEncrypted {
                ciphertext: ct.to_vec(),
                iv: iv_bytes.to_vec(),
            }),
            error_code: None,
            error_message: None,
        })
    } else {
        Ok(MediaRetryEvent {
            key,
            media: None,
            error_code: Some(404),
            error_message: Some("Failed to re-upload media (missing ciphertext)".to_string()),
        })
    }
}

pub fn decrypt_media_retry_data(
    ciphertext: &[u8],
    iv: &[u8],
    media_key: &[u8],
    msg_id: &str,
) -> Result<MediaRetryNotification, MediaError> {
    let retry_key = get_media_retry_key(media_key)?;
    let plaintext = aes_decrypt_gcm(ciphertext, &retry_key, iv, msg_id.as_bytes())?;
    Ok(MediaRetryNotification::decode(plaintext.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_encrypt_decrypt_roundtrip() {
        let original = b"imagen-de-prueba-baileys-rust-1234567890";
        let enc = encrypt_media_bytes(original, MediaType::Image).unwrap();
        assert_eq!(enc.media_key.len(), 32);
        assert_eq!(enc.file_sha256.len(), 32);
        assert_eq!(enc.file_enc_sha256.len(), 32);
        assert_eq!(enc.file_length, original.len() as u64);

        let dec = decrypt_media_bytes(&enc.encrypted, &enc.media_key, MediaType::Image).unwrap();
        assert_eq!(dec, original);

        let mut tampered = enc.encrypted.clone();
        tampered[0] ^= 0xff;
        assert!(matches!(
            decrypt_media_bytes(&tampered, &enc.media_key, MediaType::Image),
            Err(MediaError::InvalidMac)
        ));
    }

    #[tokio::test]
    async fn test_encrypted_stream_temp_files() {
        let data = b"archivo-audio-ogg-opus-rust".to_vec();
        let res = encrypted_stream(&WaMediaUpload::Bytes(data.clone()), MediaType::Audio, true)
            .await
            .unwrap();
        let enc_bytes = fs::read(&res.enc_file_path).await.unwrap();
        let dec = decrypt_media_bytes(&enc_bytes, &res.media_key, MediaType::Audio).unwrap();
        assert_eq!(dec, data);

        let orig_path = res.original_file_path.unwrap();
        assert_eq!(fs::read(&orig_path).await.unwrap(), data);

        let _ = fs::remove_file(&res.enc_file_path).await;
        let _ = fs::remove_file(&orig_path).await;
    }

    #[test]
    fn test_media_retry_roundtrip_and_helpers() {
        let media_key = [9u8; 32];
        let key = WaMessageKey {
            id: Some("MSG_MEDIA_1".to_string()),
            remote_jid: Some("573001111111@s.whatsapp.net".to_string()),
            from_me: Some(false),
            ..Default::default()
        };

        let req_node =
            encrypt_media_retry_request(&key, &media_key, "573002222222:1@s.whatsapp.net").unwrap();
        assert_eq!(req_node.tag, "receipt");
        assert_eq!(
            req_node.attrs.get("type").map(|s| s.as_str()),
            Some("server-error")
        );

        let notif = MediaRetryNotification {
            stanza_id: Some("MSG_MEDIA_1".to_string()),
            direct_path: Some("/v/t62.7118-24/sample".to_string()),
            result: Some(MediaRetryResultType::Success as i32),
            ..Default::default()
        };
        let iv = [4u8; 12];
        let retry_key = get_media_retry_key(&media_key).unwrap();
        let ct = aes_encrypt_gcm(&notif.encode_to_vec(), &retry_key, &iv, b"MSG_MEDIA_1").unwrap();

        let retry_node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([("id".to_string(), "MSG_MEDIA_1".to_string())]),
            content: Some(BinaryNodeData::List(vec![
                BinaryNode {
                    tag: "rmr".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("jid".to_string(), "573001111111@s.whatsapp.net".to_string()),
                        ("from_me".to_string(), "false".to_string()),
                    ]),
                    content: None,
                },
                BinaryNode {
                    tag: "encrypt".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![
                        BinaryNode {
                            tag: "enc_p".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::Bytes(ct)),
                        },
                        BinaryNode {
                            tag: "enc_iv".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::Bytes(iv.to_vec())),
                        },
                    ])),
                },
            ])),
        };

        let decoded_event = decode_media_retry_node(&retry_node).unwrap();
        let enc_part = decoded_event.media.unwrap();
        let dec_notif =
            decrypt_media_retry_data(&enc_part.ciphertext, &enc_part.iv, &media_key, "MSG_MEDIA_1")
                .unwrap();
        assert_eq!(
            dec_notif.direct_path.as_deref(),
            Some("/v/t62.7118-24/sample")
        );
        assert_eq!(
            get_status_code_for_media_retry(dec_notif.result.unwrap()),
            Some(200)
        );

        assert_eq!(
            encode_base64_encoded_string_for_upload("ab+c/d=="),
            "ab-c_d"
        );
        assert_eq!(extract_host("https://a.whatsapp.net/foo"), None);
        assert_eq!(
            extract_host("https://mmg.whatsapp.net/foo").as_deref(),
            Some("mmg.whatsapp.net")
        );

        let img_msg = Message {
            image_message: Some(
                ImageMessage {
                    mimetype: Some("image/jpeg".to_string()),
                    file_sha256: Some(vec![1, 2, 3]),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        assert_eq!(extension_for_media_message(&img_msg).as_deref(), Some("jpeg"));
        assert_eq!(media_message_sha256_b64(&img_msg).as_deref(), Some("AQID"));
    }
}
