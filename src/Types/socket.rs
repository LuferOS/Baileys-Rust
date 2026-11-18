use crate::defaults::{
    WaVersion, BAILEYS_VERSION, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_KEEP_ALIVE_INTERVAL_MS,
    DEFAULT_QUERY_TIMEOUT_MS, DEFAULT_WA_WEBSOCKET_URL,
};
use crate::utils::browser_utils::Browsers;

#[derive(Debug, Clone)]
pub struct SocketConfig {
    pub version: WaVersion,
    pub browser: [String; 3],
    pub wa_websocket_url: String,
    pub connect_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub default_query_timeout_ms: u64,
    pub mark_online_on_connect: bool,
    pub sync_full_history: bool,
    pub country_code: String,
    pub push_name: Option<String>,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            version: BAILEYS_VERSION,
            browser: Browsers::macos("Chrome"),
            wa_websocket_url: DEFAULT_WA_WEBSOCKET_URL.to_string(),
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            keep_alive_interval_ms: DEFAULT_KEEP_ALIVE_INTERVAL_MS,
            default_query_timeout_ms: DEFAULT_QUERY_TIMEOUT_MS,
            mark_online_on_connect: true,
            sync_full_history: true,
            country_code: "US".to_string(),
            push_name: None,
        }
    }
}
