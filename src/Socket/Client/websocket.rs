use super::types::{SocketReadyState, WebSocketError, WebSocketEvent};
use crate::defaults::DEFAULT_ORIGIN;
use crate::types::SocketConfig;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream};

enum WsCommand {
    SendBinary(Vec<u8>),
    SendText(String),
    Close,
}

#[derive(Clone)]
pub struct WebSocketSender {
    state: Arc<AtomicU8>,
    cmd_tx: mpsc::UnboundedSender<WsCommand>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl WebSocketSender {
    pub fn ready_state(&self) -> SocketReadyState {
        SocketReadyState::from(self.state.load(Ordering::SeqCst))
    }

    pub fn is_open(&self) -> bool {
        self.ready_state() == SocketReadyState::Open
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn send_bytes(&self, data: Vec<u8>) -> bool {
        self.cmd_tx.send(WsCommand::SendBinary(data)).is_ok()
    }

    pub fn send_text(&self, text: String) -> bool {
        self.cmd_tx.send(WsCommand::SendText(text)).is_ok()
    }

    pub fn close(&self) {
        self.state
            .store(SocketReadyState::Closing as u8, Ordering::SeqCst);
        let _ = self.cmd_tx.send(WsCommand::Close);
    }
}

pub struct WebSocketReceiver {
    event_rx: mpsc::UnboundedReceiver<WebSocketEvent>,
}

impl WebSocketReceiver {
    pub async fn recv(&mut self) -> Option<WebSocketEvent> {
        self.event_rx.recv().await
    }
}

pub struct WebSocketClient {
    url: String,
    config: SocketConfig,
    state: Arc<AtomicU8>,
    cmd_tx: Option<mpsc::UnboundedSender<WsCommand>>,
    event_rx: Option<mpsc::UnboundedReceiver<WebSocketEvent>>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl WebSocketClient {
    pub fn new(url: impl Into<String>, config: SocketConfig) -> Self {
        Self {
            url: url.into(),
            config,
            state: Arc::new(AtomicU8::new(SocketReadyState::Closed as u8)),
            cmd_tx: None,
            event_rx: None,
            peer_addr: None,
            local_addr: None,
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

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
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

        let mut ws_cfg = WebSocketConfig::default();
        ws_cfg.write_buffer_size = 0;
        ws_cfg.max_write_buffer_size = 256 * 1024;

        let connect_dur = Duration::from_millis(self.config.connect_timeout_ms);
        let ws_result = timeout(
            connect_dur,
            connect_async_with_config(request, Some(ws_cfg), true),
        )
        .await;

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

        let (peer_addr, local_addr) = match ws_stream.get_ref() {
            MaybeTlsStream::Plain(tcp) => (tcp.peer_addr().ok(), tcp.local_addr().ok()),
            MaybeTlsStream::Rustls(tls) => {
                let tcp = tls.get_ref().0;
                (tcp.peer_addr().ok(), tcp.local_addr().ok())
            }
            _ => (None, None),
        };
        self.peer_addr = peer_addr;
        self.local_addr = local_addr;

        let (mut write, mut read) = ws_stream.split();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<WsCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<WebSocketEvent>();

        self.state
            .store(SocketReadyState::Open as u8, Ordering::SeqCst);
        let _ = event_tx.send(WebSocketEvent::Open);

        let write_state = Arc::clone(&self.state);
        let write_event_tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(first) = cmd_rx.recv().await {
                let mut batch = Vec::with_capacity(8);
                batch.push(first);
                while batch.len() < 32 {
                    match cmd_rx.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }

                let mut closing = false;
                let mut failed: Option<String> = None;

                for cmd in batch {
                    match cmd {
                        WsCommand::SendBinary(data) => {
                            if let Err(err) = write.feed(Message::Binary(data)).await {
                                failed = Some(err.to_string());
                                break;
                            }
                        }
                        WsCommand::SendText(text) => {
                            if let Err(err) = write.feed(Message::Text(text)).await {
                                failed = Some(err.to_string());
                                break;
                            }
                        }
                        WsCommand::Close => {
                            closing = true;
                            write_state.store(SocketReadyState::Closing as u8, Ordering::SeqCst);
                            let _ = write.send(Message::Close(None)).await;
                            let _ = write.close().await;
                            write_state.store(SocketReadyState::Closed as u8, Ordering::SeqCst);
                            let _ = write_event_tx.send(WebSocketEvent::Close(None));
                            break;
                        }
                    }
                }

                if let Some(err) = failed {
                    let _ = write_event_tx.send(WebSocketEvent::Error(err));
                    break;
                }
                if closing {
                    break;
                }
                if let Err(err) = write.flush().await {
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

    pub fn split(mut self) -> Option<(WebSocketSender, WebSocketReceiver)> {
        let cmd_tx = self.cmd_tx.take()?;
        let event_rx = self.event_rx.take()?;
        Some((
            WebSocketSender {
                state: Arc::clone(&self.state),
                cmd_tx,
                peer_addr: self.peer_addr,
                local_addr: self.local_addr,
            },
            WebSocketReceiver { event_rx },
        ))
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
