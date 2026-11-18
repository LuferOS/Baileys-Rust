use crate::defaults::{NOISE_WA_HEADER, TIME_MS_DAY, TIME_MS_WEEK};
use crate::proto::{handshake_message, HandshakeMessage};
use crate::socket::client::{
    WebSocketClient, WebSocketError, WebSocketEvent, WebSocketReceiver, WebSocketSender,
};
use crate::types::{
    AuthenticationCreds, ConnectionState, ConnectionUpdate, ContactInfo, DisconnectReason,
    LastDisconnect, SocketConfig, SocketEvent,
};
use crate::utils::{
    aes_encrypt_ctr, build_pairing_qr_data, bytes_to_crockford, configure_successful_pairing,
    derive_pairing_code_key, generate_login_node, generate_md_tag_prefix,
    generate_registration_node, get_companion_platform_id, get_error_code_from_stream_error,
    now_millis, CryptoError, Curve, NoiseError, NoiseFrame, NoiseHandler, ValidateConnectionError,
};
use crate::wa_binary::{
    assert_node_error_free, encode_binary_node, get_binary_node_child, get_binary_node_children,
    jid_encode, BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError, JidServer,
    S_WHATSAPP_NET,
};
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL};
use base64::Engine;
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex};
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("websocket error: {0}")]
    WebSocket(#[from] WebSocketError),
    #[error("noise error: {0}")]
    Noise(#[from] NoiseError),
    #[error("binary node error: {0}")]
    BinaryNode(#[from] BinaryNodeError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("validate connection error: {0}")]
    ValidateConnection(#[from] ValidateConnectionError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("query timed out")]
    TimedOut,
    #[error("invalid custom pairing code: must be exactly 8 chars")]
    InvalidPairingCode,
}

struct SocketInner {
    config: SocketConfig,
    uq_tag_id: String,
    epoch: AtomicU64,
    closed: AtomicBool,
    last_date_recv_ms: AtomicU64,
    server_time_offset_ms: AtomicI64,
    ws_sender: WebSocketSender,
    noise: StdMutex<NoiseHandler>,
    creds: AsyncMutex<AuthenticationCreds>,
    pending_queries: AsyncMutex<HashMap<String, oneshot::Sender<BinaryNode>>>,
    events_tx: broadcast::Sender<SocketEvent>,
}

#[derive(Clone)]
pub struct WaSocket {
    inner: Arc<SocketInner>,
}

impl WaSocket {
    pub async fn connect(
        config: SocketConfig,
        creds: AuthenticationCreds,
    ) -> Result<Self, SocketError> {
        let mut url = config.wa_websocket_url.clone();
        if url.starts_with("wss://") {
            if let Some(routing_info) = &creds.routing_info {
                let encoded = BASE64_URL.encode(routing_info);
                let sep = if url.contains('?') { '&' } else { '?' };
                url.push_str(&format!("{}ED={}", sep, encoded));
            }
        }

        let mut ws = WebSocketClient::new(url, config.clone());
        ws.connect().await?;
        let (ws_sender, mut ws_receiver) = ws.split().ok_or(SocketError::ConnectionClosed)?;

        let ephemeral_key_pair = Curve::generate_key_pair();
        let mut noise = NoiseHandler::new(
            ephemeral_key_pair.clone(),
            &NOISE_WA_HEADER,
            creds.routing_info.as_deref(),
        );

        let hello_msg = HandshakeMessage {
            client_hello: Some(handshake_message::ClientHello {
                ephemeral: Some(ephemeral_key_pair.public),
                ..Default::default()
            }),
            ..Default::default()
        };
        let hello_frame = noise.encode_frame(&hello_msg.encode_to_vec())?;
        if !ws_sender.send_bytes(hello_frame) {
            return Err(SocketError::ConnectionClosed);
        }

        let server_hello_raw =
            Self::wait_handshake_frame(&mut ws_receiver, &mut noise, config.connect_timeout_ms)
                .await?;
        let handshake = HandshakeMessage::decode(server_hello_raw.as_slice())?;
        let server_hello = handshake
            .server_hello
            .ok_or_else(|| SocketError::HandshakeFailed("missing serverHello".to_string()))?;

        let key_enc = noise.process_handshake(&server_hello, &creds.noise_key)?;

        let client_payload = match &creds.me {
            None => generate_registration_node(&creds.signal_creds(), &config),
            Some(me) => generate_login_node(&me.id, &config)?,
        };
        let payload_enc = noise.encrypt(&client_payload.encode_to_vec())?;

        let client_finish = HandshakeMessage {
            client_finish: Some(handshake_message::ClientFinish {
                r#static: Some(key_enc),
                payload: Some(payload_enc), ..Default::default()
            }),
            ..Default::default()
        };
        let finish_frame = noise.encode_frame(&client_finish.encode_to_vec())?;
        if !ws_sender.send_bytes(finish_frame) {
            return Err(SocketError::ConnectionClosed);
        }

        noise.finish_init()?;
        let buffered_frames = noise.decode_frame(&[])?;

        let (events_tx, _) = broadcast::channel(256);
        let inner = Arc::new(SocketInner {
            config,
            uq_tag_id: generate_md_tag_prefix(),
            epoch: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            last_date_recv_ms: AtomicU64::new(now_millis()),
            server_time_offset_ms: AtomicI64::new(0),
            ws_sender,
            noise: StdMutex::new(noise),
            creds: AsyncMutex::new(creds),
            pending_queries: AsyncMutex::new(HashMap::new()),
            events_tx,
        });

        let socket = Self { inner };

        let _ = socket
            .inner
            .events_tx
            .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                connection: Some(ConnectionState::Connecting),
                received_pending_notifications: Some(false),
                ..Default::default()
            }));

        for frame in buffered_frames {
            if let NoiseFrame::Node(node) = frame {
                socket.handle_incoming_node(node).await;
            }
        }

        socket.spawn_read_loop(ws_receiver);
        socket.spawn_keep_alive_loop();

        Ok(socket)
    }

    async fn wait_handshake_frame(
        ws_receiver: &mut WebSocketReceiver,
        noise: &mut NoiseHandler,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, SocketError> {
        let dur = Duration::from_millis(timeout_ms);
        timeout(dur, async {
            loop {
                match ws_receiver.recv().await {
                    Some(WebSocketEvent::Open) => continue,
                    Some(WebSocketEvent::Message(data)) => {
                        let frames = noise.decode_frame(&data)?;
                        for frame in frames {
                            if let NoiseFrame::Raw(raw) = frame {
                                return Ok(raw);
                            }
                        }
                    }
                    Some(WebSocketEvent::Error(err)) => {
                        return Err(SocketError::HandshakeFailed(err));
                    }
                    Some(WebSocketEvent::Close(reason)) => {
                        return Err(SocketError::HandshakeFailed(
                            reason.unwrap_or_else(|| "closed during handshake".to_string()),
                        ));
                    }
                    None => return Err(SocketError::ConnectionClosed),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| SocketError::TimedOut)?
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SocketEvent> {
        self.inner.events_tx.subscribe()
    }

    pub fn generate_message_tag(&self) -> String {
        let next = self.inner.epoch.fetch_add(1, Ordering::SeqCst);
        format!("{}{}", self.inner.uq_tag_id, next)
    }

    pub fn is_open(&self) -> bool {
        !self.inner.closed.load(Ordering::SeqCst) && self.inner.ws_sender.is_open()
    }

    pub async fn creds(&self) -> AuthenticationCreds {
        self.inner.creds.lock().await.clone()
    }

    pub fn send_raw_message(&self, data: &[u8]) -> Result<(), SocketError> {
        if !self.is_open() {
            return Err(SocketError::ConnectionClosed);
        }
        let frame = {
            let mut noise = self.inner.noise.lock().unwrap();
            noise.encode_frame(data)?
        };
        if !self.inner.ws_sender.send_bytes(frame) {
            return Err(SocketError::ConnectionClosed);
        }
        Ok(())
    }

    pub fn send_node(&self, frame: &BinaryNode) -> Result<(), SocketError> {
        let buff = encode_binary_node(frame)?;
        self.send_raw_message(&buff)
    }

    pub async fn query(
        &self,
        mut node: BinaryNode,
        timeout_ms: Option<u64>,
    ) -> Result<BinaryNode, SocketError> {
        let msg_id = match node.attrs.get("id") {
            Some(id) if !id.is_empty() => id.clone(),
            _ => {
                let id = self.generate_message_tag();
                node.attrs.insert("id".to_string(), id.clone());
                id
            }
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending_queries.lock().await;
            pending.insert(msg_id.clone(), tx);
        }

        if let Err(err) = self.send_node(&node) {
            let mut pending = self.inner.pending_queries.lock().await;
            pending.remove(&msg_id);
            return Err(err);
        }

        let wait_ms = timeout_ms.unwrap_or(self.inner.config.default_query_timeout_ms);
        let response = match timeout(Duration::from_millis(wait_ms), rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => return Err(SocketError::ConnectionClosed),
            Err(_) => {
                let mut pending = self.inner.pending_queries.lock().await;
                pending.remove(&msg_id);
                return Err(SocketError::TimedOut);
            }
        };

        assert_node_error_free(&response)?;
        Ok(response)
    }

    pub async fn send_passive_iq(&self, active: bool) -> Result<BinaryNode, SocketError> {
        let tag = if active { "active" } else { "passive" };
        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("xmlns".to_string(), "passive".to_string()),
                    ("type".to_string(), "set".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: tag.to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }])),
            },
            None,
        )
        .await
    }

    pub async fn request_pairing_code(
        &self,
        phone_number: &str,
        custom_pairing_code: Option<&str>,
    ) -> Result<String, SocketError> {
        let pairing_code = match custom_pairing_code {
            Some(code) => {
                if code.len() != 8 {
                    return Err(SocketError::InvalidPairingCode);
                }
                code.to_string()
            }
            None => {
                let mut rand_bytes = [0u8; 5];
                OsRng.fill_bytes(&mut rand_bytes);
                bytes_to_crockford(&rand_bytes)
            }
        };

        let (me_id, wrapped_ephemeral, noise_pub) = {
            let mut creds = self.inner.creds.lock().await;
            creds.pairing_code = Some(pairing_code.clone());
            let jid = jid_encode(Some(phone_number), &JidServer::SWhatsappNet, None, None);
            creds.me = Some(ContactInfo {
                id: jid.clone(),
                name: Some("~".to_string()),
                lid: None,
            });

            let mut salt = [0u8; 32];
            let mut iv = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            OsRng.fill_bytes(&mut iv);
            let key = derive_pairing_code_key(&pairing_code, &salt);
            let ciphered = aes_encrypt_ctr(&creds.pairing_ephemeral_key_pair.public, &key, &iv)?;
            let mut wrapped = Vec::with_capacity(salt.len() + iv.len() + ciphered.len());
            wrapped.extend_from_slice(&salt);
            wrapped.extend_from_slice(&iv);
            wrapped.extend_from_slice(&ciphered);

            let snapshot = creds.clone();
            let _ = self
                .inner
                .events_tx
                .send(SocketEvent::CredsUpdate(Box::new(snapshot)));
            (jid, wrapped, creds.noise_key.public.clone())
        };

        let browser = &self.inner.config.browser;
        let node = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("to".to_string(), S_WHATSAPP_NET.to_string()),
                ("type".to_string(), "set".to_string()),
                ("id".to_string(), self.generate_message_tag()),
                ("xmlns".to_string(), "md".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "link_code_companion_reg".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("jid".to_string(), me_id),
                    ("stage".to_string(), "companion_hello".to_string()),
                    (
                        "should_show_push_notification".to_string(),
                        "true".to_string(),
                    ),
                ]),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "link_code_pairing_wrapped_companion_ephemeral_pub".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(wrapped_ephemeral)),
                    },
                    BinaryNode {
                        tag: "companion_server_auth_key_pub".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(noise_pub)),
                    },
                    BinaryNode {
                        tag: "companion_platform_id".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::String(get_companion_platform_id(browser))),
                    },
                    BinaryNode {
                        tag: "companion_platform_display".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::String(format!(
                            "{} ({})",
                            browser[1], browser[0]
                        ))),
                    },
                    BinaryNode {
                        tag: "link_code_pairing_nonce".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::String("0".to_string())),
                    },
                ])),
            }])),
        };

        self.send_node(&node)?;
        Ok(pairing_code)
    }

    pub fn get_unified_session_id(&self) -> String {
        let offset_ms = 3 * TIME_MS_DAY as i128;
        let now = now_millis() as i128
            + self.inner.server_time_offset_ms.load(Ordering::SeqCst) as i128;
        let id = (now + offset_ms).rem_euclid(TIME_MS_WEEK as i128);
        id.to_string()
    }

    pub fn send_unified_session(&self) -> Result<(), SocketError> {
        if !self.is_open() {
            return Ok(());
        }
        let node = BinaryNode {
            tag: "ib".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "unified_session".to_string(),
                attrs: BinaryNodeAttributes::from([("id".to_string(), self.get_unified_session_id())]),
                content: None,
            }])),
        };
        self.send_node(&node)
    }

    pub async fn logout(&self, msg: Option<&str>) -> Result<(), SocketError> {
        let jid = { self.inner.creds.lock().await.me.as_ref().map(|m| m.id.clone()) };
        if let Some(jid) = jid {
            let _ = self.send_node(&BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                    ("id".to_string(), self.generate_message_tag()),
                    ("xmlns".to_string(), "md".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "remove-companion-device".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("jid".to_string(), jid),
                        ("reason".to_string(), "user_initiated".to_string()),
                    ]),
                    content: None,
                }])),
            });
        }
        self.end(
            Some(msg.unwrap_or("Intentional Logout").to_string()),
            Some(DisconnectReason::LoggedOut as u16),
        )
        .await;
        Ok(())
    }

    pub async fn end(&self, error: Option<String>, status_code: Option<u16>) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.ws_sender.close();
        {
            let mut pending = self.inner.pending_queries.lock().await;
            pending.clear();
        }
        let _ = self
            .inner
            .events_tx
            .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                connection: Some(ConnectionState::Close),
                last_disconnect: Some(LastDisconnect {
                    error,
                    status_code,
                    timestamp_ms: now_millis(),
                }),
                ..Default::default()
            }));
    }

    fn update_server_time_offset(&self, node: &BinaryNode) {
        if let Some(t_val) = node.attrs.get("t").and_then(|s| s.parse::<i64>().ok()) {
            if t_val > 0 {
                let local_ms = now_millis() as i64;
                let offset = t_val.saturating_mul(1000).saturating_sub(local_ms);
                self.inner
                    .server_time_offset_ms
                    .store(offset, Ordering::SeqCst);
            }
        }
    }

    fn spawn_read_loop(&self, mut ws_receiver: WebSocketReceiver) {
        let socket = self.clone();
        tokio::spawn(async move {
            while let Some(event) = ws_receiver.recv().await {
                if socket.inner.closed.load(Ordering::SeqCst) {
                    break;
                }
                match event {
                    WebSocketEvent::Message(data) => {
                        let decoded = {
                            let mut noise = socket.inner.noise.lock().unwrap();
                            noise.decode_frame(&data)
                        };
                        match decoded {
                            Ok(frames) => {
                                socket
                                    .inner
                                    .last_date_recv_ms
                                    .store(now_millis(), Ordering::SeqCst);
                                for frame in frames {
                                    if let NoiseFrame::Node(node) = frame {
                                        socket.handle_incoming_node(node).await;
                                    }
                                }
                            }
                            Err(err) => {
                                socket
                                    .end(
                                        Some(err.to_string()),
                                        Some(DisconnectReason::BadSession as u16),
                                    )
                                    .await;
                                break;
                            }
                        }
                    }
                    WebSocketEvent::Error(err) => {
                        socket
                            .end(Some(err), Some(DisconnectReason::ConnectionClosed as u16))
                            .await;
                        break;
                    }
                    WebSocketEvent::Close(reason) => {
                        socket
                            .end(
                                reason.or_else(|| Some("Connection Terminated".to_string())),
                                Some(DisconnectReason::ConnectionClosed as u16),
                            )
                            .await;
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    fn spawn_keep_alive_loop(&self) {
        let socket = self.clone();
        let interval_ms = self.inner.config.keep_alive_interval_ms;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if socket.inner.closed.load(Ordering::SeqCst) {
                    break;
                }
                let last = socket.inner.last_date_recv_ms.load(Ordering::SeqCst);
                let diff = now_millis().saturating_sub(last);
                if diff > interval_ms + 5000 {
                    socket
                        .end(
                            Some("Connection was lost".to_string()),
                            Some(DisconnectReason::ConnectionLost as u16),
                        )
                        .await;
                    break;
                }
                if socket.is_open() {
                    let ping_node = BinaryNode {
                        tag: "iq".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("id".to_string(), socket.generate_message_tag()),
                            ("to".to_string(), S_WHATSAPP_NET.to_string()),
                            ("type".to_string(), "get".to_string()),
                            ("xmlns".to_string(), "w:p".to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "ping".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: None,
                        }])),
                    };
                    let _ = socket.query(ping_node, None).await;
                }
            }
        });
    }

    async fn handle_incoming_node(&self, node: BinaryNode) {
        if let Some(msg_id) = node.attrs.get("id") {
            let waiter = {
                let mut pending = self.inner.pending_queries.lock().await;
                pending.remove(msg_id)
            };
            if let Some(tx) = waiter {
                let _ = tx.send(node.clone());
            }
        }

        match node.tag.as_str() {
            "xmlstreamend" => {
                self.end(
                    Some("Connection Terminated by Server".to_string()),
                    Some(DisconnectReason::ConnectionClosed as u16),
                )
                .await;
                return;
            }
            "stream:error" => {
                let (reason, status_code) = get_error_code_from_stream_error(&node);
                self.end(
                    Some(format!("Stream Errored ({})", reason)),
                    Some(status_code),
                )
                .await;
                return;
            }
            "failure" => {
                let status_code = node
                    .attrs
                    .get("reason")
                    .and_then(|r| r.parse::<u16>().ok())
                    .unwrap_or(500);
                self.end(Some("Connection Failure".to_string()), Some(status_code))
                    .await;
                return;
            }
            "success" => {
                self.update_server_time_offset(&node);
                let _ = self.send_passive_iq(true).await;
                if let Some(lid) = node.attrs.get("lid").cloned() {
                    let mut creds = self.inner.creds.lock().await;
                    if let Some(me) = &mut creds.me {
                        me.lid = Some(lid);
                    }
                    let _ = self
                        .inner
                        .events_tx
                        .send(SocketEvent::CredsUpdate(Box::new(creds.clone())));
                }
                let _ = self
                    .inner
                    .events_tx
                    .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                        connection: Some(ConnectionState::Open),
                        ..Default::default()
                    }));
                let _ = self.send_unified_session();
            }
            "iq" => {
                if node.attrs.get("type").map(|s| s.as_str()) == Some("set")
                    && get_binary_node_child(Some(&node), "pair-device").is_some()
                {
                    self.handle_pair_device(&node).await;
                } else if get_binary_node_child(Some(&node), "pair-success").is_some() {
                    self.handle_pair_success(&node).await;
                }
            }
            "ib" => {
                if get_binary_node_child(Some(&node), "downgrade_webclient").is_some() {
                    self.end(
                        Some("Multi-device beta not joined".to_string()),
                        Some(DisconnectReason::MultideviceMismatch as u16),
                    )
                    .await;
                    return;
                }
                if get_binary_node_child(Some(&node), "offline_preview").is_some() {
                    let _ = self.send_node(&BinaryNode {
                        tag: "ib".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "offline_batch".to_string(),
                            attrs: BinaryNodeAttributes::from([(
                                "count".to_string(),
                                "100".to_string(),
                            )]),
                            content: None,
                        }])),
                    });
                }
                if let Some(edge_routing) = get_binary_node_child(Some(&node), "edge_routing") {
                    if let Some(routing_info) =
                        get_binary_node_child(Some(edge_routing), "routing_info")
                    {
                        if let Some(BinaryNodeData::Bytes(bytes)) = &routing_info.content {
                            let mut creds = self.inner.creds.lock().await;
                            creds.routing_info = Some(bytes.clone());
                            let _ = self
                                .inner
                                .events_tx
                                .send(SocketEvent::CredsUpdate(Box::new(creds.clone())));
                        }
                    }
                }
                if get_binary_node_child(Some(&node), "offline").is_some() {
                    let _ = self
                        .inner
                        .events_tx
                        .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                            received_pending_notifications: Some(true),
                            ..Default::default()
                        }));
                }
            }
            _ => {}
        }

        let _ = self.inner.events_tx.send(SocketEvent::Node(node));
    }

    async fn handle_pair_device(&self, stanza: &BinaryNode) {
        if let Some(id) = stanza.attrs.get("id").cloned() {
            let _ = self.send_node(&BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "result".to_string()),
                    ("id".to_string(), id),
                ]),
                content: None,
            });
        }

        let pair_device = get_binary_node_child(Some(stanza), "pair-device");
        let refs: Vec<String> = get_binary_node_children(pair_device, "ref")
            .into_iter()
            .filter_map(|r| match &r.content {
                Some(BinaryNodeData::Bytes(b)) => Some(String::from_utf8_lossy(b).into_owned()),
                Some(BinaryNodeData::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();

        let (noise_b64, identity_b64, adv_b64) = {
            let creds = self.inner.creds.lock().await;
            (
                BASE64.encode(&creds.noise_key.public),
                BASE64.encode(&creds.signed_identity_key.public),
                creds.adv_secret_key.clone(),
            )
        };

        let socket = self.clone();
        tokio::spawn(async move {
            let mut wait_ms = 60_000u64;
            for ref_token in refs {
                if !socket.is_open() {
                    return;
                }
                let qr = build_pairing_qr_data(
                    &ref_token,
                    &noise_b64,
                    &identity_b64,
                    &adv_b64,
                    &socket.inner.config.browser,
                );
                let _ = socket
                    .inner
                    .events_tx
                    .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                        qr: Some(qr),
                        ..Default::default()
                    }));
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                wait_ms = 20_000;
            }
            if socket.is_open() {
                socket
                    .end(
                        Some("QR refs attempts ended".to_string()),
                        Some(DisconnectReason::ConnectionLost as u16),
                    )
                    .await;
            }
        });
    }

    async fn handle_pair_success(&self, stanza: &BinaryNode) {
        self.update_server_time_offset(stanza);
        let pairing = {
            let creds = self.inner.creds.lock().await;
            configure_successful_pairing(
                stanza,
                &creds.adv_secret_key,
                &creds.signed_identity_key,
                &creds.signal_identities,
            )
        };

        match pairing {
            Ok(result) => {
                {
                    let mut creds = self.inner.creds.lock().await;
                    creds.account = Some(result.creds.account.encode_to_vec());
                    creds.me = Some(result.creds.me);
                    creds.signal_identities = result.creds.signal_identities;
                    creds.platform = result.creds.platform;
                    creds.registered = true;
                    let _ = self
                        .inner
                        .events_tx
                        .send(SocketEvent::CredsUpdate(Box::new(creds.clone())));
                }
                let _ = self
                    .inner
                    .events_tx
                    .send(SocketEvent::ConnectionUpdate(ConnectionUpdate {
                        is_new_login: Some(true),
                        qr: None,
                        ..Default::default()
                    }));
                let _ = self.send_node(&result.reply);
                let _ = self.send_unified_session();
            }
            Err(err) => {
                self.end(
                    Some(err.to_string()),
                    Some(DisconnectReason::BadSession as u16),
                )
                .await;
            }
        }
    }
}
