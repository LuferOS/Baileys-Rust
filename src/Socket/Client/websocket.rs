use super::types::{SocketReadyState, WebSocketError, WebSocketEvent};
use crate::defaults::DEFAULT_ORIGIN;
use crate::types::SocketConfig;
use futures_util::{SinkExt, StreamExt};
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

enum WsCommand {
    SendBinary(Vec<u8>),
    SendText(String),
    Close,
}

pub struct WebSocketClient {
    url: String,
    config: SocketConfig,
    state: Arc<AtomicU8>,
    cmd_tx: Option<mpsc::UnboundedSender<WsCommand>>,
    event_rx: Option<mpsc::UnboundedReceiver<WebSocketEvent>>,
}

impl WebSocketClient {
    pub fn new(url: impl Into<String>, config: SocketConfig) -> Self {
        Self {
            url: url.into(),
            config,
            state: Arc::new(AtomicU8::new(SocketReadyState::Closed as u8)),
            cmd_tx: None,
            event_rx: None,
        }
    }

    pub fn ready_state(&self) -> SocketReadyState {
        SocketReadyState::from(self.state.load(Ordering::SeqCst))
    }

    pub fn is_open(&self) -> bool {
        self.ready_state() == SocketReadyState::Open
    }

    pub fn is_closed(&self) -> bool {
        self.ready_state() == SocketReadyState::Closed
    }

    pub fn is_closing(&self) -> bool {
        self.ready_state() == SocketReadyState::Closing
    }

    pub fn is_connecting(&self) -> bool {
        self.ready_state() == SocketReadyState::Connecting
    }

    pub async fn connect(&mut self) -> Result<(), WebSocketError> {
        if self.is_open() || self.is_connecting() {
            return Ok(());
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        self.state
            .store(SocketReadyState::Connecting as u8, Ordering::SeqCst);

        let mut request = self.url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("Origin", HeaderValue::from_static(DEFAULT_ORIGIN));

        for (k, v) in &self.config.headers {
            let name = HeaderName::from_str(k)
                .map_err(|_| WebSocketError::InvalidHeaderName(k.clone()))?;
            let value = HeaderValue::from_str(v)
                .map_err(|_| WebSocketError::InvalidHeaderValue(v.clone()))?;
            request.headers_mut().insert(name, value);
        }

        let connect_dur = Duration::from_millis(self.config.connect_timeout_ms);
        let ws_result = timeout(connect_dur, connect_async(request)).await;

        let (ws_stream, _) = match ws_result {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                self.state
                    .store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                return Err(WebSocketError::Tungstenite(e));
            }
            Err(_) => {
                self.state
                    .store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                return Err(WebSocketError::Timeout);
            }
        };

        let (mut write, mut read) = ws_stream.split();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<WsCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<WebSocketEvent>();

        self.state
            .store(SocketReadyState::Open as u8, Ordering::SeqCst);
        let _ = event_tx.send(WebSocketEvent::Open);

        let write_state = Arc::clone(&self.state);
        let write_event_tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let res = match cmd {
                    WsCommand::SendBinary(data) => write.send(Message::Binary(data)).await,
                    WsCommand::SendText(text) => write.send(Message::Text(text)).await,
                    WsCommand::Close => {
                        write_state.store(SocketReadyState::Closing as u8, Ordering::SeqCst);
                        let close_res = write.send(Message::Close(None)).await;
                        let _ = write.close().await;
                        write_state.store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                        let _ = write_event_tx.send(WebSocketEvent::Close(None));
                        close_res
                    }
                };

                if let Err(err) = res {
                    let _ = write_event_tx.send(WebSocketEvent::Error(err.to_string()));
                    break;
                }
            }
        });

        let read_state = Arc::clone(&self.state);
        tokio::spawn(async move {
            while let Some(item) = read.next().await {
                match item {
                    Ok(Message::Binary(data)) => {
                        let _ = event_tx.send(WebSocketEvent::Message(data));
                    }
                    Ok(Message::Text(text)) => {
                        let _ = event_tx.send(WebSocketEvent::Text(text));
                    }
                    Ok(Message::Ping(data)) => {
                        let _ = event_tx.send(WebSocketEvent::Ping(data));
                    }
                    Ok(Message::Pong(data)) => {
                        let _ = event_tx.send(WebSocketEvent::Pong(data));
                    }
                    Ok(Message::Close(frame)) => {
                        read_state.store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                        let reason = frame.map(|f| f.reason.to_string());
                        let _ = event_tx.send(WebSocketEvent::Close(reason));
                        break;
                    }
                    Ok(Message::Frame(_)) => {}
                    Err(err) => {
                        read_state.store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                        let _ = event_tx.send(WebSocketEvent::Error(err.to_string()));
                        let _ = event_tx.send(WebSocketEvent::Close(Some(err.to_string())));
                        break;
                    }
                }
            }
            read_state.store(SocketReadyState::Closed as u8, Ordering::SeqCst);
        });

        self.cmd_tx = Some(cmd_tx);
        self.event_rx = Some(event_rx);
        Ok(())
    }

    pub fn send_bytes(&self, data: Vec<u8>) -> bool {
        if let Some(tx) = &self.cmd_tx {
            return tx.send(WsCommand::SendBinary(data)).is_ok();
        }
        false
    }

    pub fn send_text(&self, text: String) -> bool {
        if let Some(tx) = &self.cmd_tx {
            return tx.send(WsCommand::SendText(text)).is_ok();
        }
        false
    }

    pub async fn recv(&mut self) -> Option<WebSocketEvent> {
        self.event_rx.as_mut()?.recv().await
    }

    pub async fn close(&mut self) {
        if let Some(tx) = self.cmd_tx.take() {
            self.state
                .store(SocketReadyState::Closing as u8, Ordering::SeqCst);
            let _ = tx.send(WsCommand::Close);
        }
        self.state
            .store(SocketReadyState::Closed as u8, Ordering::SeqCst);
    }
}
