use super::socket::{SocketError, WaSocket};
use crate::defaults::DEFAULT_CACHE_TTL_USER_DEVICES;
use crate::proto::message::{
    AudioMessage, DeviceSentMessage, SenderKeyDistributionMessage as ProtoSkdm, VideoMessage,
};
use crate::proto::{AdvSignedDeviceIdentity, Message};
use crate::signal::{LibSignalRepository, SignalError};
use crate::types::{LidMapping, MessageCipherType, USyncDeviceEntry, WaMessage, WaMessageKey};
use crate::utils::{
    aggregate_message_keys_not_from_me, encode_newsletter_message, encode_signed_device_identity,
    encode_wa_message, extract_device_jids, generate_message_id_v2, generate_participant_hash_v2,
    generate_wa_message, normalize_message_content, parse_e2e_sessions, unix_timestamp_seconds,
    AnyMessageContent, AuthStateError, MessageGenerationError, MessageGenerationOptions,
    MultiFileAuthState, SignalUtilsError,
};
use crate::wa_binary::{
    are_jids_same_user, get_binary_node_child, get_binary_node_children, is_hosted_lid_user,
    is_hosted_pn_user, is_jid_group, is_lid_user, is_pn_user, jid_decode, jid_encode,
    jid_normalized_user, BinaryNode, BinaryNodeAttributes, BinaryNodeData, FullJid, JidServer,
    STORIES_JID, S_WHATSAPP_NET,
};
use crate::wa_usync::{USyncQuery, USyncUser};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

pub const DEF_MEDIA_HOST: &str = "mmg.whatsapp.net";

#[derive(Debug, Error)]
pub enum MessagesSendError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("signal error: {0}")]
    Signal(#[from] SignalError),
    #[error("signal utils error: {0}")]
    SignalUtils(#[from] SignalUtilsError),
    #[error("auth state error: {0}")]
    AuthState(#[from] AuthStateError),
    #[error("message generation error: {0}")]
    MessageGeneration(#[from] MessageGenerationError),
    #[error("not authenticated: missing own jid")]
    NotAuthenticated,
    #[error("invalid jid: {0}")]
    InvalidJid(String),
    #[error("missing ids in receipt")]
    MissingReceiptIds,
    #[error("missing media_conn node in server response")]
    MissingMediaConn,
    #[error("all participant encryptions failed")]
    AllEncryptionsFailed,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaHost {
    pub hostname: String,
    pub max_content_length_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct MediaConnInfo {
    pub hosts: Vec<MediaHost>,
    pub auth: String,
    pub ttl: u64,
    pub fetch_date: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageReceiptType {
    Read,
    ReadSelf,
    Sender,
    Played,
    PlayedSelf,
    Retry,
    ServerError,
    Inactive,
    PeerMsg,
    HistSync,
    Delivery,
}

impl MessageReceiptType {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            MessageReceiptType::Read => Some("read"),
            MessageReceiptType::ReadSelf => Some("read-self"),
            MessageReceiptType::Sender => Some("sender"),
            MessageReceiptType::Played => Some("played"),
            MessageReceiptType::PlayedSelf => Some("played-self"),
            MessageReceiptType::Retry => Some("retry"),
            MessageReceiptType::ServerError => Some("server-error"),
            MessageReceiptType::Inactive => Some("inactive"),
            MessageReceiptType::PeerMsg => Some("peer_msg"),
            MessageReceiptType::HistSync => Some("hist_sync"),
            MessageReceiptType::Delivery => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryParticipant {
    pub jid: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MessageRelayOptions {
    pub message_id: Option<String>,
    pub participant: Option<RetryParticipant>,
    pub additional_attributes: BinaryNodeAttributes,
    pub additional_nodes: Vec<BinaryNode>,
    pub use_user_devices_cache: Option<bool>,
    pub status_jid_list: Vec<String>,
    pub group_participants: Option<Vec<String>>,
    pub group_addressing_mode: Option<String>,
    pub group_ephemeral_duration: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWithJid {
    pub user: String,
    pub device: Option<u32>,
    pub jid: String,
}

pub struct ParticipantNodesResult {
    pub nodes: Vec<BinaryNode>,
    pub should_include_device_identity: bool,
}

pub fn get_media_type(message: &Message) -> &'static str {
    if message.image_message.is_some() {
        return "image";
    }
    if let Some(ref v) = message.video_message {
        let inner: &VideoMessage = Borrow::borrow(v);
        return if inner.gif_playback == Some(true) {
            "gif"
        } else {
            "video"
        };
    }
    if let Some(ref a) = message.audio_message {
        let inner: &AudioMessage = Borrow::borrow(a);
        return if inner.ptt == Some(true) {
            "ptt"
        } else {
            "audio"
        };
    }
    if message.contact_message.is_some() {
        return "vcard";
    }
    if message.document_message.is_some() {
        return "document";
    }
    if message.contacts_array_message.is_some() {
        return "contact_array";
    }
    if message.live_location_message.is_some() {
        return "livelocation";
    }
    if message.sticker_message.is_some() {
        return "sticker";
    }
    if message.list_message.is_some() {
        return "list";
    }
    if message.list_response_message.is_some() {
        return "list_response";
    }
    if message.buttons_response_message.is_some() {
        return "buttons_response";
    }
    if message.order_message.is_some() {
        return "order";
    }
    if message.product_message.is_some() {
        return "product";
    }
    if message.interactive_response_message.is_some() {
        return "native_flow_response";
    }
    if message.group_invite_message.is_some() {
        return "url";
    }
    ""
}

pub fn get_message_type(message: &Message) -> &'static str {
    let normalized = normalize_message_content(message);

    if normalized.reaction_message.is_some() || normalized.enc_reaction_message.is_some() {
        return "reaction";
    }

    if normalized.poll_creation_message.is_some()
        || normalized.poll_creation_message_v2.is_some()
        || normalized.poll_creation_message_v3.is_some()
        || normalized.poll_update_message.is_some()
    {
        return "poll";
    }

    if normalized.event_message.is_some() {
        return "event";
    }

    if !get_media_type(&normalized).is_empty() {
        return "media";
    }

    "text"
}

pub fn build_receipt_node(
    jid: &str,
    participant: Option<&str>,
    message_ids: &[String],
    receipt_type: MessageReceiptType,
) -> Result<BinaryNode, MessagesSendError> {
    if message_ids.is_empty() {
        return Err(MessagesSendError::MissingReceiptIds);
    }

    let mut attrs = BinaryNodeAttributes::new();
    attrs.insert("id".to_string(), message_ids[0].clone());

    if matches!(
        receipt_type,
        MessageReceiptType::Read | MessageReceiptType::ReadSelf
    ) {
        attrs.insert("t".to_string(), unix_timestamp_seconds().to_string());
    }

    if receipt_type == MessageReceiptType::Sender
        && (is_pn_user(Some(jid)) || is_lid_user(Some(jid)))
    {
        attrs.insert("recipient".to_string(), jid.to_string());
        if let Some(p) = participant {
            attrs.insert("to".to_string(), p.to_string());
        }
    } else {
        attrs.insert("to".to_string(), jid.to_string());
        if let Some(p) = participant {
            attrs.insert("participant".to_string(), p.to_string());
        }
    }

    if let Some(t) = receipt_type.as_str() {
        attrs.insert("type".to_string(), t.to_string());
    }

    let content = if message_ids.len() > 1 {
        let items: Vec<BinaryNode> = message_ids[1..]
            .iter()
            .map(|id| BinaryNode {
                tag: "item".to_string(),
                attrs: BinaryNodeAttributes::from([("id".to_string(), id.clone())]),
                content: None,
            })
            .collect();
        Some(BinaryNodeData::List(vec![BinaryNode {
            tag: "list".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(items)),
        }]))
    } else {
        None
    };

    Ok(BinaryNode {
        tag: "receipt".to_string(),
        attrs,
        content,
    })
}

pub async fn encrypt_participant_nodes(
    recipient_jids: &[String],
    message: &Message,
    extra_attrs: &BinaryNodeAttributes,
    dsm_message: Option<&Message>,
    me_id: &str,
    me_lid: Option<&str>,
    signal_repository: &LibSignalRepository,
) -> Result<ParticipantNodesResult, MessagesSendError> {
    if recipient_jids.is_empty() {
        return Ok(ParticipantNodesResult {
            nodes: Vec::new(),
            should_include_device_identity: false,
        });
    }

    let own_pn_user = jid_decode(me_id).map(|d| d.user);
    let own_lid_user = me_lid.and_then(jid_decode).map(|d| d.user);

    let mut nodes = Vec::with_capacity(recipient_jids.len());
    let mut should_include_device_identity = false;

    for jid in recipient_jids {
        if jid.is_empty() {
            continue;
        }

        let mut msg_to_encrypt = message;
        if let Some(dsm) = dsm_message {
            if let Some(target_user) = jid_decode(jid).map(|d| d.user) {
                let is_own_user = own_pn_user.as_deref() == Some(target_user.as_str())
                    || own_lid_user.as_deref() == Some(target_user.as_str());
                let is_exact_sender = jid == me_id || me_lid == Some(jid.as_str());
                if is_own_user && !is_exact_sender {
                    msg_to_encrypt = dsm;
                }
            }
        }

        let bytes = encode_wa_message(msg_to_encrypt);
        if let Ok(encrypted) = signal_repository.encrypt_message(jid, &bytes).await {
            if encrypted.cipher_type == MessageCipherType::Pkmsg {
                should_include_device_identity = true;
            }
            let mut enc_attrs = extra_attrs.clone();
            enc_attrs.insert("v".to_string(), "2".to_string());
            enc_attrs.insert("type".to_string(), encrypted.cipher_type.as_str().to_string());

            nodes.push(BinaryNode {
                tag: "to".to_string(),
                attrs: BinaryNodeAttributes::from([("jid".to_string(), jid.clone())]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "enc".to_string(),
                    attrs: enc_attrs,
                    content: Some(BinaryNodeData::Bytes(encrypted.ciphertext)),
                }])),
            });
        }
    }

    if !recipient_jids.is_empty() && nodes.is_empty() {
        return Err(MessagesSendError::AllEncryptionsFailed);
    }

    Ok(ParticipantNodesResult {
        nodes,
        should_include_device_identity,
    })
}

pub struct MessagesSocket {
    pub socket: WaSocket,
    pub auth: Arc<MultiFileAuthState>,
    pub signal_repository: Arc<LibSignalRepository>,
    user_devices_cache: AsyncMutex<HashMap<String, (Instant, Vec<FullJid>)>>,
    media_conn: AsyncMutex<Option<MediaConnInfo>>,
    media_host: AsyncMutex<String>,
}

impl MessagesSocket {
    pub fn new(
        socket: WaSocket,
        auth: Arc<MultiFileAuthState>,
        signal_repository: Arc<LibSignalRepository>,
    ) -> Self {
        Self {
            socket,
            auth,
            signal_repository,
            user_devices_cache: AsyncMutex::new(HashMap::new()),
            media_conn: AsyncMutex::new(None),
            media_host: AsyncMutex::new(DEF_MEDIA_HOST.to_string()),
        }
    }

    pub async fn get_media_host(&self) -> String {
        self.media_host.lock().await.clone()
    }

    pub async fn refresh_media_conn(&self, force_get: bool) -> Result<MediaConnInfo, MessagesSendError> {
        let mut cache = self.media_conn.lock().await;
        if let Some(ref existing) = *cache {
            if !force_get && existing.fetch_date.elapsed() < Duration::from_secs(existing.ttl) {
                return Ok(existing.clone());
            }
        }

        let result = self
            .socket
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:m".to_string()),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "media_conn".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: None,
                    }])),
                },
                None,
            )
            .await?;

        let media_conn_node = get_binary_node_child(Some(&result), "media_conn")
            .ok_or(MessagesSendError::MissingMediaConn)?;

        let hosts: Vec<MediaHost> = get_binary_node_children(Some(media_conn_node), "host")
            .into_iter()
            .filter_map(|h| {
                let hostname = h.attrs.get("hostname")?.clone();
                let max_bytes = h
                    .attrs
                    .get("maxContentLengthBytes")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                Some(MediaHost {
                    hostname,
                    max_content_length_bytes: max_bytes,
                })
            })
            .collect();

        if let Some(first_host) = hosts.first() {
            *self.media_host.lock().await = first_host.hostname.clone();
        }

        let info = MediaConnInfo {
            hosts,
            auth: media_conn_node
                .attrs
                .get("auth")
                .cloned()
                .unwrap_or_default(),
            ttl: media_conn_node
                .attrs
                .get("ttl")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300),
            fetch_date: Instant::now(),
        };

        *cache = Some(info.clone());
        Ok(info)
    }

    pub fn send_receipt(
        &self,
        jid: &str,
        participant: Option<&str>,
        message_ids: &[String],
        receipt_type: MessageReceiptType,
    ) -> Result<(), MessagesSendError> {
        let node = build_receipt_node(jid, participant, message_ids, receipt_type)?;
        self.socket.send_node(&node)?;
        Ok(())
    }

    pub fn send_receipts(
        &self,
        keys: &[WaMessageKey],
        receipt_type: MessageReceiptType,
    ) -> Result<(), MessagesSendError> {
        let recps = aggregate_message_keys_not_from_me(keys);
        for recp in recps {
            self.send_receipt(
                &recp.jid,
                recp.participant.as_deref(),
                &recp.message_ids,
                receipt_type,
            )?;
        }
        Ok(())
    }

    pub async fn issue_privacy_tokens(
        &self,
        jids: &[String],
        timestamp: Option<u64>,
    ) -> Result<BinaryNode, MessagesSendError> {
        let t = timestamp.unwrap_or_else(unix_timestamp_seconds).to_string();
        let token_nodes: Vec<BinaryNode> = jids
            .iter()
            .map(|jid| BinaryNode {
                tag: "token".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("jid".to_string(), jid_normalized_user(Some(jid))),
                    ("t".to_string(), t.clone()),
                    ("type".to_string(), "trusted_contact".to_string()),
                ]),
                content: None,
            })
            .collect();

        let result = self
            .socket
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "privacy".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "tokens".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(token_nodes)),
                    }])),
                },
                None,
            )
            .await?;

        Ok(result)
    }

    pub async fn assert_sessions(
        &self,
        jids: &[String],
        force: bool,
    ) -> Result<bool, MessagesSendError> {
        let unique: Vec<String> = jids
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let mut jids_requiring_fetch = Vec::new();
        for jid in unique {
            if !force && self.signal_repository.validate_session(&jid).await.exists {
                continue;
            }
            jids_requiring_fetch.push(jid);
        }

        if jids_requiring_fetch.is_empty() {
            return Ok(false);
        }

        let mut wire_jids: Vec<String> = jids_requiring_fetch
            .iter()
            .filter(|j| is_lid_user(Some(j)) || is_hosted_lid_user(Some(j)))
            .cloned()
            .collect();

        let pn_jids: Vec<String> = jids_requiring_fetch
            .iter()
            .filter(|j| is_pn_user(Some(j)) || is_hosted_pn_user(Some(j)))
            .cloned()
            .collect();

        if !pn_jids.is_empty() {
            if let Some(mapped) = self.signal_repository.lid_mapping.get_lids_for_pns(&pn_jids).await {
                let mapped_pns: HashSet<String> = mapped.iter().map(|m| m.pn.clone()).collect();
                for m in mapped {
                    wire_jids.push(m.lid);
                }
                for pn in pn_jids {
                    if !mapped_pns.contains(&pn) {
                        wire_jids.push(pn);
                    }
                }
            } else {
                wire_jids.extend(pn_jids);
            }
        }

        if wire_jids.is_empty() {
            return Ok(false);
        }

        let user_nodes: Vec<BinaryNode> = wire_jids
            .into_iter()
            .map(|jid| {
                let mut attrs = BinaryNodeAttributes::from([("jid".to_string(), jid)]);
                if force {
                    attrs.insert("reason".to_string(), "identity".to_string());
                }
                BinaryNode {
                    tag: "user".to_string(),
                    attrs,
                    content: None,
                }
            })
            .collect();

        let result = self
            .socket
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("xmlns".to_string(), "encrypt".to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "key".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(user_nodes)),
                    }])),
                },
                None,
            )
            .await?;

        let sessions = parse_e2e_sessions(&result)?;
        for (jid, session) in sessions {
            self.signal_repository
                .inject_e2e_session(&jid, &session)
                .await?;
        }

        Ok(true)
    }

    pub async fn get_usync_devices(
        &self,
        jids: &[String],
        use_cache: bool,
        ignore_zero_devices: bool,
    ) -> Result<Vec<DeviceWithJid>, MessagesSendError> {
        let mut device_results = Vec::new();
        let mut to_fetch = Vec::new();

        let ttl = Duration::from_secs(DEFAULT_CACHE_TTL_USER_DEVICES);

        {
            let mut cache = self.user_devices_cache.lock().await;
            cache.retain(|_, (ts, _)| ts.elapsed() < ttl);

            for jid in jids {
                let Some(decoded) = jid_decode(jid) else {
                    continue;
                };
                if let Some(device) = decoded.device {
                    if !decoded.user.is_empty() {
                        device_results.push(DeviceWithJid {
                            user: decoded.user,
                            device: Some(device),
                            jid: jid.clone(),
                        });
                        continue;
                    }
                }

                let normalized = jid_normalized_user(Some(jid));
                if use_cache {
                    if let Some((_, cached_devs)) = cache.get(&decoded.user) {
                        for d in cached_devs {
                            device_results.push(DeviceWithJid {
                                user: d.user.clone(),
                                device: d.device,
                                jid: jid_encode(Some(&d.user), &d.server, d.device, None),
                            });
                        }
                        continue;
                    }
                }
                to_fetch.push(normalized);
            }
        }

        if to_fetch.is_empty() {
            return Ok(device_results);
        }

        let mut query = USyncQuery::new()
            .with_context("message")
            .with_device_protocol()
            .with_lid_protocol();
        for jid in &to_fetch {
            query = query.with_user(USyncUser::new().with_id(jid.clone()));
        }

        let Some(result) = self.socket.execute_usync_query(&query).await? else {
            return Ok(device_results);
        };

        let lid_mappings: Vec<LidMapping> = result
            .list
            .iter()
            .filter_map(|item| {
                let lid = item.lid()?.to_string();
                Some(LidMapping {
                    pn: item.id.clone(),
                    lid,
                })
            })
            .collect();

        if !lid_mappings.is_empty() {
            let _ = self
                .signal_repository
                .lid_mapping
                .store_lid_pn_mappings(&lid_mappings)
                .await;
            let lids: Vec<String> = lid_mappings.iter().map(|m| m.lid.clone()).collect();
            let _ = self.assert_sessions(&lids, true).await;
        }

        let creds = self.socket.creds().await;
        let me = creds.me.ok_or(MessagesSendError::NotAuthenticated)?;
        let my_lid = me.lid.as_deref().unwrap_or("");

        let usync_entries: Vec<USyncDeviceEntry> = result
            .list
            .iter()
            .map(|item| USyncDeviceEntry {
                id: item.id.clone(),
                devices: item.devices().map(|d| d.to_parsed_device_info()),
            })
            .collect();

        let extracted = extract_device_jids(&usync_entries, &me.id, my_lid, ignore_zero_devices);
        let mut device_map: HashMap<String, Vec<FullJid>> = HashMap::new();
        for item in extracted {
            device_results.push(DeviceWithJid {
                user: item.user.clone(),
                device: item.device,
                jid: jid_encode(Some(&item.user), &item.server, item.device, None),
            });
            device_map.entry(item.user.clone()).or_default().push(item);
        }

        {
            let mut cache = self.user_devices_cache.lock().await;
            let now = Instant::now();
            for (user, devs) in &device_map {
                cache.insert(user.clone(), (now, devs.clone()));
            }
        }

        let mut device_list_updates: HashMap<String, Option<Value>> = HashMap::new();
        for (user_id, devs) in device_map {
            if !devs.is_empty() {
                let list: Vec<String> = devs
                    .into_iter()
                    .map(|d| d.device.unwrap_or(0).to_string())
                    .collect();
                device_list_updates.insert(user_id, Some(serde_json::to_value(list)?));
            }
        }
        if !device_list_updates.is_empty() {
            let mut batch = HashMap::new();
            batch.insert("device-list".to_string(), device_list_updates);
            let _ = self.auth.set_keys(batch).await;
        }

        Ok(device_results)
    }

    async fn fetch_group_participants_basic(
        &self,
        group_jid: &str,
    ) -> Result<(Vec<String>, String, Option<u32>), MessagesSendError> {
        let res = self
            .socket
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), group_jid.to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("xmlns".to_string(), "w:g2".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "query".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "request".to_string(),
                            "interactive".to_string(),
                        )]),
                        content: None,
                    }])),
                },
                None,
            )
            .await?;

        let group_node = get_binary_node_child(Some(&res), "group");
        let addressing_mode = group_node
            .and_then(|g| g.attrs.get("addressing_mode").cloned())
            .unwrap_or_else(|| "lid".to_string());
        let ephemeral = get_binary_node_child(group_node, "ephemeral")
            .and_then(|e| e.attrs.get("expiration"))
            .and_then(|v| v.parse::<u32>().ok());
        let participants: Vec<String> = get_binary_node_children(group_node, "participant")
            .into_iter()
            .filter_map(|p| p.attrs.get("jid").cloned())
            .collect();

        Ok((participants, addressing_mode, ephemeral))
    }

    pub async fn relay_message(
        &self,
        jid: &str,
        message: &Message,
        mut opts: MessageRelayOptions,
    ) -> Result<String, MessagesSendError> {
        let creds = self.socket.creds().await;
        let me = creds.me.as_ref().ok_or(MessagesSendError::NotAuthenticated)?;
        let me_id = me.id.clone();
        let me_lid = me.lid.clone();

        let decoded_dest =
            jid_decode(jid).ok_or_else(|| MessagesSendError::InvalidJid(jid.to_string()))?;
        let is_group = decoded_dest.server == JidServer::GUs;
        let is_status = jid == STORIES_JID;
        let is_lid = decoded_dest.server == JidServer::Lid;
        let is_newsletter = decoded_dest.server == JidServer::Newsletter;
        let is_group_or_status = is_group || is_status;
        let is_retry_resend = opts.participant.is_some();

        let msg_id = opts
            .message_id
            .clone()
            .unwrap_or_else(|| generate_message_id_v2(Some(&me_id)));
        let use_user_devices_cache = opts.use_user_devices_cache.unwrap_or(true);
        let destination_jid = if is_status {
            STORIES_JID.to_string()
        } else {
            jid.to_string()
        };

        let mut should_include_device_identity = is_retry_resend;
        let mut participants_nodes: Vec<BinaryNode> = Vec::new();
        let mut binary_node_content: Vec<BinaryNode> = Vec::new();
        let mut extra_attrs = BinaryNodeAttributes::new();

        let media_type = get_media_type(message);
        if !media_type.is_empty() {
            extra_attrs.insert("mediatype".to_string(), media_type.to_string());
        }

        if is_newsletter {
            let bytes = encode_newsletter_message(message);
            binary_node_content.push(BinaryNode {
                tag: "plaintext".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(bytes)),
            });
            let mut attrs = opts.additional_attributes.clone();
            attrs.insert("to".to_string(), jid.to_string());
            attrs.insert("id".to_string(), msg_id.clone());
            attrs.insert("type".to_string(), get_message_type(message).to_string());
            self.socket.send_node(&BinaryNode {
                tag: "message".to_string(),
                attrs,
                content: Some(BinaryNodeData::List(binary_node_content)),
            })?;
            return Ok(msg_id);
        }

        let normalized = normalize_message_content(message);
        if normalized.pin_in_chat_message.is_some() || normalized.reaction_message.is_some() {
            extra_attrs.insert("decrypt-fail".to_string(), "hide".to_string());
        }

        let me_msg = Message {
            device_sent_message: Some(
                DeviceSentMessage {
                    destination_jid: Some(destination_jid.clone()),
                    message: Some(message.clone().into()),
                    ..Default::default()
                }
                .into(),
            ),
            message_context_info: message.message_context_info.clone(),
            ..Default::default()
        };

        if let Some(ref retry_part) = opts.participant {
            if !is_group && !is_status {
                opts.additional_attributes
                    .insert("device_fanout".to_string(), "false".to_string());
            }

            let is_part_lid = is_lid_user(Some(&retry_part.jid));
            let is_me = are_jids_same_user(
                Some(&retry_part.jid),
                if is_part_lid {
                    me_lid.as_deref()
                } else {
                    Some(me_id.as_str())
                },
            );

            let mut message_to_send = message.clone();
            if is_group_or_status {
                let mut group_sender_identity: Option<String> = None;
                if let Some(ref lid) = me_lid {
                    if self
                        .signal_repository
                        .has_sender_key(&destination_jid, lid)
                        .await
                        .unwrap_or(false)
                    {
                        group_sender_identity = Some(lid.clone());
                    }
                }
                if group_sender_identity.is_none()
                    && self
                        .signal_repository
                        .has_sender_key(&destination_jid, &me_id)
                        .await
                        .unwrap_or(false)
                {
                    group_sender_identity = Some(me_id.clone());
                }

                if let Some(sender_id) = group_sender_identity {
                    if let Ok(skdm) = self
                        .signal_repository
                        .get_sender_key_distribution_message(&destination_jid, &sender_id)
                        .await
                    {
                        message_to_send.sender_key_distribution_message = Some(ProtoSkdm {
                            group_id: Some(destination_jid.clone()),
                            axolotl_sender_key_distribution_message: Some(skdm),
                        });
                    }
                }
            }

            let encoded = if is_me {
                encode_wa_message(&Message {
                    device_sent_message: Some(
                        DeviceSentMessage {
                            destination_jid: Some(destination_jid.clone()),
                            message: Some(message_to_send.into()),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    ..Default::default()
                })
            } else {
                encode_wa_message(&message_to_send)
            };

            let encrypted = self
                .signal_repository
                .encrypt_message(&retry_part.jid, &encoded)
                .await?;
            binary_node_content.push(BinaryNode {
                tag: "enc".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("v".to_string(), "2".to_string()),
                    (
                        "type".to_string(),
                        encrypted.cipher_type.as_str().to_string(),
                    ),
                    ("count".to_string(), retry_part.count.to_string()),
                ]),
                content: Some(BinaryNodeData::Bytes(encrypted.ciphertext)),
            });
        } else if is_group_or_status {
            let (mut participants_list, addr_mode, ephem) =
                if let Some(list) = opts.group_participants.clone() {
                    (
                        list,
                        opts.group_addressing_mode
                            .clone()
                            .unwrap_or_else(|| "lid".to_string()),
                        opts.group_ephemeral_duration,
                    )
                } else if !is_status {
                    self.fetch_group_participants_basic(jid).await?
                } else {
                    (Vec::new(), "lid".to_string(), None)
                };

            if is_status {
                participants_list.extend(opts.status_jid_list.clone());
            }

            if let Some(exp) = ephem.filter(|&e| e > 0) {
                opts.additional_attributes
                    .insert("expiration".to_string(), exp.to_string());
            }

            if is_group {
                opts.additional_attributes
                    .entry("addressing_mode".to_string())
                    .or_insert_with(|| addr_mode.clone());
            }

            let mut sender_key_map: HashMap<String, bool> = if !is_status {
                let stored = self
                    .auth
                    .get_keys("sender-key-memory", &[jid.to_string()])
                    .await;
                stored
                    .get(jid)
                    .and_then(|v| v.as_ref())
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default()
            } else {
                HashMap::new()
            };

            let devices = self
                .get_usync_devices(&participants_list, use_user_devices_cache, false)
                .await?;

            let bytes = encode_wa_message(message);
            let group_addr_mode = opts
                .additional_attributes
                .get("addressing_mode")
                .map(|s| s.as_str())
                .unwrap_or(addr_mode.as_str());
            let group_sender_identity = if group_addr_mode == "lid" {
                me_lid.as_deref().unwrap_or(&me_id)
            } else {
                &me_id
            };

            let enc_group = self
                .signal_repository
                .encrypt_group_message(&destination_jid, group_sender_identity, &bytes)
                .await?;

            let mut sender_key_recipients = Vec::new();
            for dev in &devices {
                let has_key = sender_key_map.get(&dev.jid).copied().unwrap_or(false);
                if !has_key
                    && !is_hosted_lid_user(Some(&dev.jid))
                    && !is_hosted_pn_user(Some(&dev.jid))
                    && dev.device != Some(99)
                {
                    sender_key_recipients.push(dev.jid.clone());
                    sender_key_map.insert(dev.jid.clone(), true);
                }
            }

            if !sender_key_recipients.is_empty() {
                let sender_key_msg = Message {
                    sender_key_distribution_message: Some(ProtoSkdm {
                        group_id: Some(destination_jid.clone()),
                        axolotl_sender_key_distribution_message: Some(
                            enc_group.sender_key_distribution_message,
                        ),
                    }),
                    ..Default::default()
                };

                self.assert_sessions(&sender_key_recipients, false).await?;
                let res = encrypt_participant_nodes(
                    &sender_key_recipients,
                    &sender_key_msg,
                    &extra_attrs,
                    None,
                    &me_id,
                    me_lid.as_deref(),
                    &self.signal_repository,
                )
                .await?;
                should_include_device_identity =
                    should_include_device_identity || res.should_include_device_identity;
                participants_nodes.extend(res.nodes);
            }

            let mut enc_attrs = extra_attrs.clone();
            enc_attrs.insert("v".to_string(), "2".to_string());
            enc_attrs.insert("type".to_string(), "skmsg".to_string());
            binary_node_content.push(BinaryNode {
                tag: "enc".to_string(),
                attrs: enc_attrs,
                content: Some(BinaryNodeData::Bytes(enc_group.ciphertext)),
            });

            if !is_status {
                let mut map_entries = HashMap::new();
                map_entries.insert(jid.to_string(), Some(serde_json::to_value(&sender_key_map)?));
                let mut batch = HashMap::new();
                batch.insert("sender-key-memory".to_string(), map_entries);
                let _ = self.auth.set_keys(batch).await;
            }
        } else {
            let is_peer = opts
                .additional_attributes
                .get("category")
                .map(|s| s.as_str())
                == Some("peer");

            let devices = if !is_peer {
                let sender_identity = if is_lid {
                    if let Some(ref lid) = me_lid {
                        jid_encode(
                            jid_decode(lid).map(|d| d.user).as_deref(),
                            &JidServer::Lid,
                            None,
                            None,
                        )
                    } else {
                        jid_encode(
                            jid_decode(&me_id).map(|d| d.user).as_deref(),
                            &JidServer::SWhatsappNet,
                            None,
                            None,
                        )
                    }
                } else {
                    jid_encode(
                        jid_decode(&me_id).map(|d| d.user).as_deref(),
                        &JidServer::SWhatsappNet,
                        None,
                        None,
                    )
                };
                self.get_usync_devices(&[sender_identity, jid.to_string()], true, false)
                    .await?
            } else {
                let target_server = if is_lid {
                    JidServer::Lid
                } else {
                    JidServer::SWhatsappNet
                };
                vec![DeviceWithJid {
                    user: decoded_dest.user.clone(),
                    device: Some(0),
                    jid: jid_encode(Some(&decoded_dest.user), &target_server, Some(0), None),
                }]
            };

            let me_pn_user = jid_decode(&me_id).map(|d| d.user);
            let me_lid_user = me_lid.as_deref().and_then(jid_decode).map(|d| d.user);

            let mut all_recipients = Vec::new();
            let mut me_recipients = Vec::new();
            let mut other_recipients = Vec::new();

            for dev in devices {
                let is_exact_sender =
                    dev.jid == me_id || me_lid.as_deref() == Some(dev.jid.as_str());
                if is_exact_sender {
                    continue;
                }
                let is_me = me_pn_user.as_deref() == Some(dev.user.as_str())
                    || me_lid_user.as_deref() == Some(dev.user.as_str());
                if is_me {
                    me_recipients.push(dev.jid.clone());
                } else {
                    other_recipients.push(dev.jid.clone());
                }
                all_recipients.push(dev.jid);
            }

            self.assert_sessions(&all_recipients, false).await?;

            let res_me = encrypt_participant_nodes(
                &me_recipients,
                &me_msg,
                &extra_attrs,
                None,
                &me_id,
                me_lid.as_deref(),
                &self.signal_repository,
            )
            .await?;
            let res_other = encrypt_participant_nodes(
                &other_recipients,
                message,
                &extra_attrs,
                Some(&me_msg),
                &me_id,
                me_lid.as_deref(),
                &self.signal_repository,
            )
            .await?;

            participants_nodes.extend(res_me.nodes);
            participants_nodes.extend(res_other.nodes);
            should_include_device_identity = should_include_device_identity
                || res_me.should_include_device_identity
                || res_other.should_include_device_identity;

            if !all_recipients.is_empty() {
                opts.additional_attributes.insert(
                    "phash".to_string(),
                    generate_participant_hash_v2(&all_recipients),
                );
            }
        }

        if !participants_nodes.is_empty() {
            if opts
                .additional_attributes
                .get("category")
                .map(|s| s.as_str())
                == Some("peer")
            {
                if let Some(BinaryNodeData::List(inner)) = &participants_nodes[0].content {
                    if let Some(first_enc) = inner.first() {
                        binary_node_content.push(first_enc.clone());
                    }
                }
            } else {
                binary_node_content.push(BinaryNode {
                    tag: "participants".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(participants_nodes)),
                });
            }
        }

        if should_include_device_identity {
            if let Some(account_bytes) = &creds.account {
                if let Ok(account) = AdvSignedDeviceIdentity::decode(account_bytes.as_slice()) {
                    let encoded = encode_signed_device_identity(&account, true);
                    binary_node_content.push(BinaryNode {
                        tag: "device-identity".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(encoded)),
                    });
                }
            }
        }

        if !opts.additional_nodes.is_empty() {
            binary_node_content.extend(opts.additional_nodes);
        }

        let mut stanza_attrs = opts.additional_attributes;
        stanza_attrs.insert("id".to_string(), msg_id.clone());
        stanza_attrs.insert("type".to_string(), get_message_type(message).to_string());

        if let Some(ref retry_part) = opts.participant {
            if is_jid_group(Some(&destination_jid)) {
                stanza_attrs.insert("to".to_string(), destination_jid);
                stanza_attrs.insert("participant".to_string(), retry_part.jid.clone());
            } else if are_jids_same_user(Some(&retry_part.jid), Some(&me_id)) {
                stanza_attrs.insert("to".to_string(), retry_part.jid.clone());
                stanza_attrs.insert("recipient".to_string(), destination_jid);
            } else {
                stanza_attrs.insert("to".to_string(), retry_part.jid.clone());
            }
        } else {
            stanza_attrs.insert("to".to_string(), destination_jid);
        }

        let stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: stanza_attrs,
            content: Some(BinaryNodeData::List(binary_node_content)),
        };

        self.socket.send_node(&stanza)?;
        Ok(msg_id)
    }

    pub async fn send_message(
        &self,
        jid: &str,
        content: AnyMessageContent,
        mut options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let creds = self.socket.creds().await;
        let user_jid = creds
            .me
            .as_ref()
            .map(|m| m.id.clone())
            .ok_or(MessagesSendError::NotAuthenticated)?;

        let mut additional_attributes = BinaryNodeAttributes::new();
        let mut additional_nodes = Vec::new();

        match &content {
            AnyMessageContent::Delete(key) => {
                if is_jid_group(key.remote_jid.as_deref()) && key.from_me != Some(true) {
                    additional_attributes.insert("edit".to_string(), "8".to_string());
                } else {
                    additional_attributes.insert("edit".to_string(), "7".to_string());
                }
            }
            AnyMessageContent::Pin(_) => {
                additional_attributes.insert("edit".to_string(), "2".to_string());
            }
            AnyMessageContent::Poll(_) => {
                additional_nodes.push(BinaryNode {
                    tag: "meta".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "polltype".to_string(),
                        "creation".to_string(),
                    )]),
                    content: None,
                });
            }
            _ => {}
        }

        if options.edit.is_some() {
            additional_attributes.insert("edit".to_string(), "1".to_string());
        }

        options.user_jid = Some(user_jid.clone());
        if options.message_id.is_none() {
            options.message_id = Some(generate_message_id_v2(Some(&user_jid)));
        }

        let full_msg = generate_wa_message(jid, content, &options)?;
        let proto_msg = full_msg
            .message
            .as_ref()
            .ok_or(MessageGenerationError::NoContent)?;

        additional_nodes.extend(crate::utils::extract_experimental_nodes(proto_msg));

        self.relay_message(
            jid,
            proto_msg,
            MessageRelayOptions {
                message_id: full_msg.key.id.clone(),
                additional_attributes,
                additional_nodes,
                ..Default::default()
            },
        )
        .await?;

        Ok(full_msg)
    }

    pub async fn send_interactive(
        &self,
        jid: &str,
        input: &crate::utils::InteractiveInput,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let msg = crate::utils::build_interactive_message(input);
        self.send_message(jid, AnyMessageContent::Raw(msg), options)
            .await
    }

    pub async fn send_webview(
        &self,
        jid: &str,
        title: impl Into<String>,
        body: impl Into<String>,
        footer: Option<String>,
        button_label: impl Into<String>,
        url: impl Into<String>,
        in_app: bool,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let msg = crate::utils::build_webview_message(title, body, footer, button_label, url, in_app);
        self.send_message(jid, AnyMessageContent::Raw(msg), options)
            .await
    }

    pub async fn send_carousel(
        &self,
        jid: &str,
        body: Option<String>,
        footer: Option<String>,
        cards: Vec<crate::utils::InteractiveInput>,
        wrap_view_once: bool,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let msg = crate::utils::build_carousel_message(body, footer, cards, wrap_view_once);
        self.send_message(jid, AnyMessageContent::Raw(msg), options)
            .await
    }

    pub async fn send_rich_response(
        &self,
        jid: &str,
        input: &crate::utils::RichResponseInput,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let msg = crate::utils::build_rich_response_message(input);
        self.send_message(jid, AnyMessageContent::Raw(msg), options)
            .await
    }

    pub async fn send_ai_rich(
        &self,
        jid: &str,
        builder: &crate::utils::AiRichBuilder,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let msg = builder.build_message();
        self.send_message(jid, AnyMessageContent::Raw(msg), options)
            .await
    }

    pub async fn send_ai_rich_html(
        &self,
        jid: &str,
        title: impl Into<String>,
        footer: impl Into<String>,
        html: impl Into<String>,
        options: MessageGenerationOptions,
    ) -> Result<WaMessage, MessagesSendError> {
        let builder = crate::utils::AiRichBuilder::new()
            .title(title)
            .footer(footer)
            .add_html_section(html, Vec::new());
        self.send_ai_rich(jid, &builder, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::{ImageMessage, ReactionMessage};
    use crate::types::{E2ESession, E2ESessionPreKey, E2ESessionSignedPreKey};
    use crate::utils::crypto::{generate_signal_pub_key, Curve};
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;

    #[test]
    fn test_message_and_media_type_detection() {
        let text_msg = Message {
            conversation: Some("hola".to_string()),
            ..Default::default()
        };
        assert_eq!(get_message_type(&text_msg), "text");
        assert_eq!(get_media_type(&text_msg), "");

        let react_msg = Message {
            reaction_message: Some(ReactionMessage::default().into()),
            ..Default::default()
        };
        assert_eq!(get_message_type(&react_msg), "reaction");

        let img_msg = Message {
            image_message: Some(ImageMessage::default().into()),
            ..Default::default()
        };
        assert_eq!(get_message_type(&img_msg), "media");
        assert_eq!(get_media_type(&img_msg), "image");

        let ptt_msg = Message {
            audio_message: Some(
                AudioMessage {
                    ptt: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        assert_eq!(get_media_type(&ptt_msg), "ptt");
    }

    #[test]
    fn test_build_receipt_node_multiple_ids() {
        let node = build_receipt_node(
            "1203630001@g.us",
            Some("573001@s.whatsapp.net"),
            &["ID1".to_string(), "ID2".to_string(), "ID3".to_string()],
            MessageReceiptType::Read,
        )
        .unwrap();

        assert_eq!(node.tag, "receipt");
        assert_eq!(node.attrs.get("id").map(|s| s.as_str()), Some("ID1"));
        assert_eq!(node.attrs.get("type").map(|s| s.as_str()), Some("read"));
        assert!(node.attrs.contains_key("t"));
        let list = get_binary_node_child(Some(&node), "list").unwrap();
        assert_eq!(get_binary_node_children(Some(list), "item").len(), 2);
    }

    #[tokio::test]
    async fn test_encrypt_participant_nodes() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir_a = std::env::temp_dir().join(format!("baileys_rs_send_a_{}", suffix));
        let dir_b = std::env::temp_dir().join(format!("baileys_rs_send_b_{}", suffix));

        let auth_a = Arc::new(use_multi_file_auth_state(&dir_a).await.unwrap());
        let auth_b = Arc::new(use_multi_file_auth_state(&dir_b).await.unwrap());
        let bob_pk = Curve::generate_key_pair();

        let repo_a = LibSignalRepository::new(Arc::clone(&auth_a), None);
        let bob_jid = "573002222222@s.whatsapp.net";
        let bob_bundle = E2ESession {
            registration_id: auth_b.creds.registration_id,
            identity_key: generate_signal_pub_key(&auth_b.creds.signed_identity_key.public),
            signed_pre_key: E2ESessionSignedPreKey {
                key_id: auth_b.creds.signed_pre_key.key_id,
                public_key: generate_signal_pub_key(&auth_b.creds.signed_pre_key.key_pair.public),
                signature: auth_b.creds.signed_pre_key.signature.clone(),
            },
            pre_key: Some(E2ESessionPreKey {
                key_id: 1,
                public_key: generate_signal_pub_key(&bob_pk.public),
            }),
        };
        repo_a.inject_e2e_session(bob_jid, &bob_bundle).await.unwrap();

        let msg = Message {
            conversation: Some("envio directo rust".to_string()),
            ..Default::default()
        };
        let res = encrypt_participant_nodes(
            &[bob_jid.to_string()],
            &msg,
            &BinaryNodeAttributes::new(),
            None,
            "573001111111@s.whatsapp.net",
            None,
            &repo_a,
        )
        .await
        .unwrap();

        assert_eq!(res.nodes.len(), 1);
        assert!(res.should_include_device_identity);
        assert_eq!(res.nodes[0].tag, "to");
        assert_eq!(
            res.nodes[0].attrs.get("jid").map(|s| s.as_str()),
            Some(bob_jid)
        );

        let _ = tokio::fs::remove_dir_all(&dir_a).await;
        let _ = tokio::fs::remove_dir_all(&dir_b).await;
    }
}
