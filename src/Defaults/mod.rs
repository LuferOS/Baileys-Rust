use crate::proto::history_sync::HistorySyncType;

pub type WaVersion = [u32; 3];

pub const BAILEYS_VERSION: WaVersion = [2, 3000, 1043857760];
pub const UNAUTHORIZED_CODES: [u16; 3] = [401, 403, 419];

pub const DEFAULT_WA_WEBSOCKET_URL: &str = "wss://web.whatsapp.com/ws/chat";
pub const DEFAULT_ORIGIN: &str = "https://web.whatsapp.com";
pub const CALL_VIDEO_PREFIX: &str = "https://call.whatsapp.com/video/";
pub const CALL_AUDIO_PREFIX: &str = "https://call.whatsapp.com/voice/";
pub const DEF_CALLBACK_PREFIX: &str = "CB:";
pub const DEF_TAG_PREFIX: &str = "TAG:";
pub const PHONE_CONNECTION_CB: &str = "CB:Pong";

pub const WA_ADV_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 0];
pub const WA_ADV_DEVICE_SIG_PREFIX: [u8; 2] = [6, 1];
pub const WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 5];
pub const WA_ADV_HOSTED_DEVICE_SIG_PREFIX: [u8; 2] = [6, 6];

pub const WA_DEFAULT_EPHEMERAL: u32 = 7 * 24 * 60 * 60;
pub const STATUS_EXPIRY_SECONDS: u32 = 24 * 60 * 60;
pub const PLACEHOLDER_MAX_AGE_SECONDS: u32 = 14 * 24 * 60 * 60;

pub const NOISE_MODE: &[u8] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";
pub const DICT_VERSION: u8 = 3;
pub const KEY_BUNDLE_TYPE: [u8; 1] = [5];
pub const NOISE_WA_HEADER: [u8; 4] = [87, 65, 6, DICT_VERSION];

pub const WA_CERT_SERIAL: u32 = 0;
pub const WA_CERT_ISSUER: &str = "WhatsAppLongTerm1";
pub const WA_CERT_PUBLIC_KEY: [u8; 32] = [
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71,
    0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c,
    0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
];

pub const PROCESSABLE_HISTORY_TYPES: [HistorySyncType; 7] = [
    HistorySyncType::InitialBootstrap,
    HistorySyncType::PushName,
    HistorySyncType::Recent,
    HistorySyncType::Full,
    HistorySyncType::OnDemand,
    HistorySyncType::NonBlockingData,
    HistorySyncType::InitialStatusV3,
];

pub const DEFAULT_CACHE_TTL_SIGNAL_STORE: u64 = 5 * 60;
pub const DEFAULT_CACHE_TTL_MSG_RETRY: u64 = 60 * 60;
pub const DEFAULT_CACHE_TTL_CALL_OFFER: u64 = 5 * 60;
pub const DEFAULT_CACHE_TTL_USER_DEVICES: u64 = 5 * 60;

pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 20_000;
pub const DEFAULT_KEEP_ALIVE_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_QUERY_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_RETRY_REQUEST_DELAY_MS: u64 = 250;
pub const DEFAULT_MAX_MSG_RETRY_COUNT: u32 = 5;
pub const HISTORY_SYNC_PAUSED_TIMEOUT_MS: u64 = 120_000;
pub const MIN_PREKEY_COUNT: usize = 5;
pub const INITIAL_PREKEY_COUNT: usize = 812;
pub const UPLOAD_TIMEOUT_MS: u64 = 30_000;

pub const TIME_MS_MINUTE: u64 = 60 * 1000;
pub const TIME_MS_HOUR: u64 = 60 * 60 * 1000;
pub const TIME_MS_DAY: u64 = 24 * 60 * 60 * 1000;
pub const TIME_MS_WEEK: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    Audio,
    Document,
    Gif,
    Image,
    Ppic,
    Product,
    Ptt,
    Sticker,
    Video,
    ThumbnailDocument,
    ThumbnailImage,
    ThumbnailVideo,
    ThumbnailLink,
    MdMsgHist,
    MdAppState,
    ProductCatalogImage,
    PaymentBgImage,
    Ptv,
    BizCoverPhoto,
}

impl MediaType {
    pub fn path(&self) -> Option<&'static str> {
        match self {
            MediaType::Image | MediaType::Sticker | MediaType::ThumbnailLink => Some("/mms/image"),
            MediaType::Video => Some("/mms/video"),
            MediaType::Document => Some("/mms/document"),
            MediaType::Audio => Some("/mms/audio"),
            MediaType::ProductCatalogImage => Some("/product/image"),
            MediaType::MdAppState => Some(""),
            MediaType::MdMsgHist => Some("/mms/md-app-state"),
            MediaType::BizCoverPhoto => Some("/pps/biz-cover-photo"),
            _ => None,
        }
    }

    pub fn hkdf_key(&self) -> &'static str {
        match self {
            MediaType::Audio | MediaType::Ptt => "Audio",
            MediaType::Document => "Document",
            MediaType::Gif | MediaType::Video | MediaType::Ptv => "Video",
            MediaType::Image | MediaType::Product | MediaType::Sticker | MediaType::BizCoverPhoto => "Image",
            MediaType::Ppic | MediaType::ProductCatalogImage => "",
            MediaType::ThumbnailDocument => "Document Thumbnail",
            MediaType::ThumbnailImage => "Image Thumbnail",
            MediaType::ThumbnailVideo => "Video Thumbnail",
            MediaType::ThumbnailLink => "Link Thumbnail",
            MediaType::MdMsgHist => "History",
            MediaType::MdAppState => "App State",
            MediaType::PaymentBgImage => "Payment Background",
        }
    }
}
