use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketReadyState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
}

impl From<u8> for SocketReadyState {
    fn from(value: u8) -> Self {
        match value {
            0 => SocketReadyState::Connecting,
            1 => SocketReadyState::Open,
            2 => SocketReadyState::Closing,
            _ => SocketReadyState::Closed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketEvent {
    Open,
    Message(Vec<u8>),
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<String>),
    Error(String),
}

#[derive(Debug, Error)]
pub enum WebSocketError {
    #[error("websocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(String),
    #[error("connection timed out")]
    Timeout,
}
