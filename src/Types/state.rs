use crate::types::AuthenticationCreds;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum DisconnectReason {
    ConnectionClosed = 428,
    ConnectionLost = 408,
    ConnectionReplaced = 440,
    LoggedOut = 401,
    BadSession = 500,
    RestartRequired = 515,
    MultideviceMismatch = 411,
    Forbidden = 403,
    UnavailableService = 503,
}

impl DisconnectReason {
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            428 => Some(Self::ConnectionClosed),
            408 => Some(Self::ConnectionLost),
            440 => Some(Self::ConnectionReplaced),
            401 => Some(Self::LoggedOut),
            500 => Some(Self::BadSession),
            515 => Some(Self::RestartRequired),
            411 => Some(Self::MultideviceMismatch),
            403 => Some(Self::Forbidden),
            503 => Some(Self::UnavailableService),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Connecting,
    Open,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastDisconnect {
    pub error: Option<String>,
    pub status_code: Option<u16>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionUpdate {
    pub connection: Option<ConnectionState>,
    pub last_disconnect: Option<LastDisconnect>,
    pub is_new_login: Option<bool>,
    pub qr: Option<String>,
    pub received_pending_notifications: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum SocketEvent {
    ConnectionUpdate(ConnectionUpdate),
    CredsUpdate(Box<AuthenticationCreds>),
    Node(crate::wa_binary::BinaryNode),
}
