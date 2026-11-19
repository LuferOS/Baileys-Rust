use crate::signal::LibSignalRepository;
use crate::socket::{MessagesRecvSocket, MessagesSocket, RecvEvent, WaSocket};
use crate::types::{
    ConnectionState, DisconnectReason, SocketConfig, SocketEvent, WaMessage, WaPresence,
};
use crate::utils::{
    extract_call_telemetry, get_next_pre_keys_node, unix_timestamp_seconds,
    use_multi_file_auth_state, Browsers, CallTelemetry,
};
use crate::wa_binary::BinaryNode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct SubBotConfig {
    pub session_id: String,
    pub auth_dir: PathBuf,
    pub pair_phone: Option<String>,
    pub wa_version: [u32; 3],
    pub browser: [String; 3],
    pub mark_online: bool,
    pub auto_reconnect: bool,
    pub connect_timeout_ms: u64,
    pub default_query_timeout_ms: u64,
}

impl SubBotConfig {
    pub fn new(
        session_id: impl Into<String>,
        auth_dir: impl Into<PathBuf>,
        wa_version: [u32; 3],
    ) -> Self {
        Self {
            session_id: session_id.into(),
            auth_dir: auth_dir.into(),
            pair_phone: None,
            wa_version,
            browser: Browsers::macos("Chrome"),
            mark_online: true,
            auto_reconnect: true,
            connect_timeout_ms: 8_000,
            default_query_timeout_ms: 8_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubBotStatus {
    pub session_id: String,
    pub jid: Option<String>,
    pub connected: bool,
    pub peer_addr: Option<String>,
    pub reconnect_count: u64,
    pub started_at: u64,
    pub last_disconnect_code: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum SubBotEvent {
    Qr {
        session_id: String,
        qr: String,
    },
    PairingCode {
        session_id: String,
        code: String,
    },
    Connected {
        session_id: String,
        jid: Option<String>,
        peer_addr: Option<SocketAddr>,
    },
    Disconnected {
        session_id: String,
        status_code: Option<u16>,
        will_reconnect: bool,
    },
    Message {
        session_id: String,
        message: WaMessage,
        is_offline: bool,
    },
    Call {
        session_id: String,
        telemetry: CallTelemetry,
    },
    Node {
        session_id: String,
        node: BinaryNode,
    },
}

struct SubBotEntry {
    stop_flag: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    reconnect_count: Arc<AtomicU64>,
    started_at: u64,
    jid: Arc<RwLock<Option<String>>>,
    peer_addr: Arc<RwLock<Option<SocketAddr>>>,
    last_disconnect_code: Arc<RwLock<Option<u16>>>,
    messages: Arc<RwLock<Option<Arc<MessagesSocket>>>>,
    task: JoinHandle<()>,
}

pub struct SubBotManager {
    sessions: Arc<RwLock<HashMap<String, SubBotEntry>>>,
    events_tx: broadcast::Sender<SubBotEvent>,
}

impl Default for SubBotManager {
    fn default() -> Self {
        Self::new(2048)
    }
}

impl SubBotManager {
    pub fn new(channel_capacity: usize) -> Self {
        let (events_tx, _) = broadcast::channel(channel_capacity.max(64));
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            events_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SubBotEvent> {
        self.events_tx.subscribe()
    }

    pub async fn active_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn get_messages_socket(&self, session_id: &str) -> Option<Arc<MessagesSocket>> {
        let map = self.sessions.read().await;
        let entry = map.get(session_id)?;
        let sock = entry.messages.read().await.clone();
        sock
    }

    pub async fn list_statuses(&self) -> Vec<SubBotStatus> {
        let map = self.sessions.read().await;
        let mut out = Vec::with_capacity(map.len());
        for (id, entry) in map.iter() {
            out.push(SubBotStatus {
                session_id: id.clone(),
                jid: entry.jid.read().await.clone(),
                connected: entry.connected.load(Ordering::Relaxed),
                peer_addr: entry.peer_addr.read().await.map(|a| a.to_string()),
                reconnect_count: entry.reconnect_count.load(Ordering::Relaxed),
                started_at: entry.started_at,
                last_disconnect_code: *entry.last_disconnect_code.read().await,
            });
        }
        out
    }

    pub async fn stop(&self, session_id: &str) -> bool {
        let entry = self.sessions.write().await.remove(session_id);
        let Some(entry) = entry else {
            return false;
        };
        entry.stop_flag.store(true, Ordering::SeqCst);
        if let Some(msg_sock) = entry.messages.read().await.clone() {
            msg_sock.socket.end(Some("subbot_stopped".to_string()), None).await;
        }
        entry.task.abort();
        true
    }

    pub async fn stop_all(&self) {
        let ids: Vec<String> = self.sessions.read().await.keys().cloned().collect();
        for id in ids {
            let _ = self.stop(&id).await;
        }
    }

    pub async fn spawn(&self, cfg: SubBotConfig) -> Result<(), String> {
        {
            let map = self.sessions.read().await;
            if map.contains_key(&cfg.session_id) {
                return Err(format!("subbot {} ya esta activo", cfg.session_id));
            }
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(false));
        let reconnect_count = Arc::new(AtomicU64::new(0));
        let jid_slot = Arc::new(RwLock::new(None));
        let peer_slot = Arc::new(RwLock::new(None));
        let code_slot = Arc::new(RwLock::new(None));
        let msg_slot = Arc::new(RwLock::new(None));

        let stop_clone = Arc::clone(&stop_flag);
        let conn_clone = Arc::clone(&connected);
        let reconn_clone = Arc::clone(&reconnect_count);
        let jid_clone = Arc::clone(&jid_slot);
        let peer_clone = Arc::clone(&peer_slot);
        let code_clone = Arc::clone(&code_slot);
        let msg_clone = Arc::clone(&msg_slot);
        let tx = self.events_tx.clone();
        let session_id = cfg.session_id.clone();

        let task = tokio::spawn(async move {
            let mut backoff_ms: u64 = 250;

            while !stop_clone.load(Ordering::SeqCst) {
                let auth = match use_multi_file_auth_state(&cfg.auth_dir).await {
                    Ok(a) => Arc::new(a),
                    Err(_) => {
                        if !cfg.auto_reconnect {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(5_000);
                        continue;
                    }
                };

                let registered = auth.creds.registered;
                let mut sock_cfg = SocketConfig::default();
                sock_cfg.version = cfg.wa_version;
                sock_cfg.browser = cfg.browser.clone();
                sock_cfg.mark_online_on_connect = cfg.mark_online;
                sock_cfg.connect_timeout_ms = cfg.connect_timeout_ms;
                sock_cfg.default_query_timeout_ms = cfg.default_query_timeout_ms;

                let socket = match WaSocket::connect(sock_cfg, auth.creds.clone()).await {
                    Ok(s) => s,
                    Err(_) => {
                        if !cfg.auto_reconnect {
                            break;
                        }
                        reconn_clone.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(5_000);
                        continue;
                    }
                };

                let peer = socket.peer_addr();
                *peer_clone.write().await = peer;

                let signal_repo = Arc::new(LibSignalRepository::new(Arc::clone(&auth), None));
                let messages = Arc::new(MessagesSocket::new(
                    socket,
                    Arc::clone(&auth),
                    Arc::clone(&signal_repo),
                ));
                *msg_clone.write().await = Some(Arc::clone(&messages));

                let recv = Arc::new(MessagesRecvSocket::new(Arc::clone(&messages)));
                let mut socket_rx = messages.socket.subscribe();
                let mut recv_rx = recv.subscribe();
                let activated = Arc::new(AtomicBool::new(false));

                if !registered {
                    if let Some(ref phone) = cfg.pair_phone {
                        if !phone.is_empty() {
                            let msg_ref = Arc::clone(&messages);
                            let phone_num = phone.clone();
                            let tx_pair = tx.clone();
                            let sid = session_id.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(350)).await;
                                if let Ok(code) =
                                    msg_ref.socket.request_pairing_code(&phone_num, None).await
                                {
                                    let _ = tx_pair.send(SubBotEvent::PairingCode {
                                        session_id: sid,
                                        code,
                                    });
                                }
                            });
                        }
                    }
                }

                let tx_recv = tx.clone();
                let sid_recv = session_id.clone();
                let recv_task = tokio::spawn(async move {
                    loop {
                        match recv_rx.recv().await {
                            Ok(RecvEvent::MessageUpsert {
                                message,
                                is_offline,
                            }) => {
                                let _ = tx_recv.send(SubBotEvent::Message {
                                    session_id: sid_recv.clone(),
                                    message,
                                    is_offline,
                                });
                            }
                            Ok(_) => {}
                            Err(RecvError::Lagged(_)) => {}
                            Err(RecvError::Closed) => break,
                        }
                    }
                });

                let mut should_reconnect = cfg.auto_reconnect;
                let mut disconnect_code: Option<u16> = None;

                while !stop_clone.load(Ordering::SeqCst) {
                    match socket_rx.recv().await {
                        Ok(SocketEvent::ConnectionUpdate(upd)) => {
                            if let Some(qr) = upd.qr {
                                let _ = tx.send(SubBotEvent::Qr {
                                    session_id: session_id.clone(),
                                    qr,
                                });
                            }
                            if let Some(ConnectionState::Open) = upd.connection {
                                backoff_ms = 250;
                                if !activated.swap(true, Ordering::SeqCst) {
                                    let msg_ref = Arc::clone(&messages);
                                    let auth_ref = Arc::clone(&auth);
                                    let dir_ref = cfg.auth_dir.clone();
                                    let conn_ref = Arc::clone(&conn_clone);
                                    let jid_ref = Arc::clone(&jid_clone);
                                    let tx_open = tx.clone();
                                    let sid_open = session_id.clone();
                                    tokio::spawn(async move {
                                        let mut creds_now = msg_ref.socket.creds().await;
                                        let prekey_exists = dir_ref.join("pre-key-1.json").exists();
                                        if creds_now.first_unuploaded_pre_key_id <= 1
                                            && !prekey_exists
                                        {
                                            if let Ok(pk) =
                                                get_next_pre_keys_node(&msg_ref.auth, 30).await
                                            {
                                                if msg_ref
                                                    .socket
                                                    .query(pk.node, Some(4_000))
                                                    .await
                                                    .is_ok()
                                                {
                                                    creds_now.first_unuploaded_pre_key_id =
                                                        pk.update.first_unuploaded_pre_key_id;
                                                    creds_now.next_pre_key_id =
                                                        pk.update.next_pre_key_id;
                                                    let _ = auth_ref.write_creds(&creds_now).await;
                                                }
                                            }
                                        }
                                        let _ = tokio::join!(
                                            msg_ref.socket.send_passive_iq(true),
                                            msg_ref
                                                .socket
                                                .send_presence_update(WaPresence::Available, None),
                                        );
                                        let warm = Arc::clone(&msg_ref);
                                        tokio::spawn(async move {
                                            let _ = warm.refresh_media_conn(false).await;
                                        });
                                        let jid_str = creds_now.me.as_ref().map(|m| m.id.clone());
                                        *jid_ref.write().await = jid_str.clone();
                                        conn_ref.store(true, Ordering::Relaxed);
                                        let _ = tx_open.send(SubBotEvent::Connected {
                                            session_id: sid_open,
                                            jid: jid_str,
                                            peer_addr: peer,
                                        });
                                    });
                                }
                            }
                            if let Some(ConnectionState::Close) = upd.connection {
                                disconnect_code =
                                    upd.last_disconnect.as_ref().and_then(|d| d.status_code);
                                *code_clone.write().await = disconnect_code;
                                should_reconnect = cfg.auto_reconnect
                                    && disconnect_code != Some(DisconnectReason::LoggedOut as u16);
                                break;
                            }
                        }
                        Ok(SocketEvent::CredsUpdate(creds)) => {
                            let auth_ref = Arc::clone(&auth);
                            tokio::spawn(async move {
                                let _ = auth_ref.write_creds(&creds).await;
                            });
                        }
                        Ok(SocketEvent::Node(node)) => {
                            if let Some(telemetry) = extract_call_telemetry(&node) {
                                let _ = tx.send(SubBotEvent::Call {
                                    session_id: session_id.clone(),
                                    telemetry,
                                });
                            }
                            let _ = tx.send(SubBotEvent::Node {
                                session_id: session_id.clone(),
                                node: node.clone(),
                            });
                            let r = Arc::clone(&recv);
                            tokio::spawn(async move {
                                let _ = r.process_node(&node).await;
                            });
                        }
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }

                recv_task.abort();
                conn_clone.store(false, Ordering::Relaxed);
                *msg_clone.write().await = None;

                let will_reconnect = should_reconnect && !stop_clone.load(Ordering::SeqCst);
                let _ = tx.send(SubBotEvent::Disconnected {
                    session_id: session_id.clone(),
                    status_code: disconnect_code,
                    will_reconnect,
                });

                if !will_reconnect {
                    break;
                }
                reconn_clone.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(5_000);
            }
        });

        let entry = SubBotEntry {
            stop_flag,
            connected,
            reconnect_count,
            started_at: unix_timestamp_seconds(),
            jid: jid_slot,
            peer_addr: peer_slot,
            last_disconnect_code: code_slot,
            messages: msg_slot,
            task,
        };

        self.sessions
            .write()
            .await
            .insert(cfg.session_id, entry);
        Ok(())
    }
}
