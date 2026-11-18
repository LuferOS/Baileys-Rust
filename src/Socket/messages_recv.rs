use super::groups::extract_group_metadata;
use super::messages_send::{MessageReceiptType, MessagesSendError, MessagesSocket};
use super::socket::SocketError;
use crate::defaults::{
    DEFAULT_MAX_MSG_RETRY_COUNT, KEY_BUNDLE_TYPE, MIN_PREKEY_COUNT, STATUS_EXPIRY_SECONDS,
};
use crate::proto::message::{protocol_message, ProtocolMessage};
use crate::proto::{web_message_info, AdvSignedDeviceIdentity, Message};
use crate::types::{LidMapping, WaMessage, WaMessageKey};
use crate::utils::{
    aes_decrypt_ctr, aes_encrypt_gcm, build_ack_stanza, decode_message_node, decrypt_message_node,
    derive_pairing_code_key, encode_big_endian, encode_signed_device_identity,
    extract_addressing_context, extract_e2e_session_from_retry_receipt, get_next_pre_keys,
    get_next_pre_keys_node, hkdf, unix_timestamp_seconds, xmpp_pre_key, xmpp_signed_pre_key,
    CryptoError, Curve, DecodeMessageError, NackReason, SignalUtilsError, MISSING_KEYS_ERROR_TEXT,
    NO_MESSAGE_FOUND_ERROR_TEXT, SERVER_ERROR_MESSAGE_ACCOUNT_RESTRICTION,
    SERVER_ERROR_SMAX_INVALID,
};
use crate::wa_binary::{
    are_jids_same_user, get_all_binary_node_children, get_binary_node_child,
    get_binary_node_child_buffer, get_binary_node_child_string, get_binary_node_child_uint,
    get_binary_node_children, is_jid_group, is_jid_newsletter, is_jid_status_broadcast,
    is_lid_user, is_pn_user, jid_decode, jid_normalized_user, BinaryNode, BinaryNodeAttributes,
    BinaryNodeData, S_WHATSAPP_NET,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prost::Message as ProstMessage;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

#[derive(Debug, Error)]
pub enum MessagesRecvError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("messages send error: {0}")]
    MessagesSend(#[from] MessagesSendError),
    #[error("decode message error: {0}")]
    DecodeMessage(#[from] DecodeMessageError),
    #[error("signal utils error: {0}")]
    SignalUtils(#[from] SignalUtilsError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("missing call info in call node")]
    MissingCallInfo,
    #[error("invalid buffer in link code companion reg")]
    InvalidLinkCodeBuffer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaCallEvent {
    pub chat_id: String,
    pub from: String,
    pub caller_pn: Option<String>,
    pub id: String,
    pub timestamp_secs: u64,
    pub offline: bool,
    pub status: String,
    pub is_video: bool,
    pub is_group: bool,
    pub group_jid: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum RecvEvent {
    MessageUpsert {
        message: WaMessage,
        is_offline: bool,
    },
    MessageStatusUpdate {
        key: WaMessageKey,
        status: i32,
        timestamp: Option<u64>,
    },
    MessageReceiptUpdate {
        key: WaMessageKey,
        user_jid: String,
        status: i32,
        timestamp: Option<u64>,
    },
    Call(WaCallEvent),
    BadAck {
        key: WaMessageKey,
        error: String,
    },
}

pub fn get_status_from_receipt_type(receipt_type: Option<&str>) -> Option<i32> {
    match receipt_type {
        None => Some(web_message_info::Status::DeliveryAck as i32),
        Some("read") | Some("read-self") => Some(web_message_info::Status::Read as i32),
        Some("played") | Some("played-self") => Some(web_message_info::Status::Played as i32),
        Some("sender") => Some(web_message_info::Status::ServerAck as i32),
        _ => None,
    }
}

pub fn get_call_status_from_node(node: &BinaryNode) -> String {
    match node.tag.as_str() {
        "offer" | "offer_notice" => "offer".to_string(),
        "terminate" => {
            if node.attrs.get("reason").map(|s| s.as_str()) == Some("timeout") {
                "timeout".to_string()
            } else {
                "terminate".to_string()
            }
        }
        "reject" => "reject".to_string(),
        "accept" => "accept".to_string(),
        other => other.to_string(),
    }
}

pub fn parse_call_event(node: &BinaryNode) -> Result<WaCallEvent, MessagesRecvError> {
    let info_child = get_all_binary_node_children(node)
        .first()
        .ok_or(MessagesRecvError::MissingCallInfo)?;

    let status = get_call_status_from_node(info_child);
    let call_id = info_child
        .attrs
        .get("call-id")
        .cloned()
        .unwrap_or_default();
    let from = info_child
        .attrs
        .get("from")
        .or_else(|| info_child.attrs.get("call-creator"))
        .cloned()
        .unwrap_or_default();

    let latency_ms = if status == "relaylatency" {
        info_child
            .attrs
            .get("latency")
            .or_else(|| info_child.attrs.get("latency_ms"))
            .or_else(|| info_child.attrs.get("latency-ms"))
            .and_then(|v| v.parse::<u64>().ok())
    } else {
        None
    };

    let is_video = get_binary_node_child(Some(info_child), "video").is_some();
    let group_jid = info_child.attrs.get("group-jid").cloned();
    let is_group = info_child.attrs.get("type").map(|s| s.as_str()) == Some("group")
        || group_jid.is_some();

    Ok(WaCallEvent {
        chat_id: node.attrs.get("from").cloned().unwrap_or_default(),
        from,
        caller_pn: info_child.attrs.get("caller_pn").cloned(),
        id: call_id,
        timestamp_secs: node
            .attrs
            .get("t")
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0),
        offline: node.attrs.contains_key("offline"),
        status,
        is_video,
        is_group,
        group_jid,
        latency_ms,
    })
}

pub fn handle_group_notification_node(
    full_node: &BinaryNode,
    child: &BinaryNode,
    msg: &mut WaMessage,
) {
    let acting_participant_lid = full_node.attrs.get("participant").cloned();
    let acting_participant_pn = full_node.attrs.get("participant_pn").cloned();

    let affected_participant_lid = get_binary_node_child(Some(child), "participant")
        .and_then(|p| p.attrs.get("jid").cloned())
        .or_else(|| acting_participant_lid.clone());
    let affected_participant_pn = get_binary_node_child(Some(child), "participant")
        .and_then(|p| p.attrs.get("phone_number").cloned())
        .or_else(|| acting_participant_pn.clone());

    match child.tag.as_str() {
        "create" => {
            if let Ok(metadata) = extract_group_metadata(child) {
                msg.message_stub_type = Some(web_message_info::StubType::GroupCreate as i32);
                msg.message_stub_parameters = vec![metadata.subject];
                msg.key.participant = metadata.owner;
                msg.key.participant_alt = metadata.owner_pn;
            }
        }
        "ephemeral" | "not_ephemeral" => {
            let expiration = child
                .attrs
                .get("expiration")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            msg.message = Some(Message {
                protocol_message: Some(
                    ProtocolMessage {
                        r#type: Some(protocol_message::Type::EphemeralSetting as i32),
                        ephemeral_expiration: Some(expiration),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            });
        }
        "modify" => {
            let old_numbers: Vec<String> = get_binary_node_children(Some(child), "participant")
                .into_iter()
                .filter_map(|p| p.attrs.get("jid").cloned())
                .collect();
            msg.message_stub_parameters = old_numbers;
            msg.message_stub_type =
                Some(web_message_info::StubType::GroupParticipantChangeNumber as i32);
        }
        "promote" | "demote" | "remove" | "add" | "leave" => {
            let mut stub_type = match child.tag.as_str() {
                "promote" => web_message_info::StubType::GroupParticipantPromote as i32,
                "demote" => web_message_info::StubType::GroupParticipantDemote as i32,
                "remove" => web_message_info::StubType::GroupParticipantRemove as i32,
                "add" => web_message_info::StubType::GroupParticipantAdd as i32,
                _ => web_message_info::StubType::GroupParticipantLeave as i32,
            };

            let participants: Vec<serde_json::Value> =
                get_binary_node_children(Some(child), "participant")
                    .into_iter()
                    .filter_map(|p| {
                        let jid = p.attrs.get("jid")?.clone();
                        let phone_number = p
                            .attrs
                            .get("phone_number")
                            .filter(|pn| is_lid_user(Some(&jid)) && is_pn_user(Some(pn)))
                            .cloned();
                        let lid = p
                            .attrs
                            .get("lid")
                            .filter(|l| is_pn_user(Some(&jid)) && is_lid_user(Some(l)))
                            .cloned();
                        Some(serde_json::json!({
                            "id": jid,
                            "phoneNumber": phone_number,
                            "lid": lid,
                            "admin": p.attrs.get("type")
                        }))
                    })
                    .collect();

            if participants.len() == 1 && child.tag == "remove" {
                if let Some(first_id) = participants[0].get("id").and_then(|v| v.as_str()) {
                    if are_jids_same_user(Some(first_id), acting_participant_lid.as_deref())
                        || are_jids_same_user(Some(first_id), acting_participant_pn.as_deref())
                    {
                        stub_type = web_message_info::StubType::GroupParticipantLeave as i32;
                    }
                }
            }

            msg.message_stub_type = Some(stub_type);
            msg.message_stub_parameters = participants
                .into_iter()
                .map(|p| p.to_string())
                .collect();
        }
        "subject" => {
            msg.message_stub_type = Some(web_message_info::StubType::GroupChangeSubject as i32);
            if let Some(subj) = child.attrs.get("subject") {
                msg.message_stub_parameters = vec![subj.clone()];
            }
        }
        "description" => {
            msg.message_stub_type = Some(web_message_info::StubType::GroupChangeDescription as i32);
            if let Some(desc) = get_binary_node_child_string(Some(child), "body") {
                msg.message_stub_parameters = vec![desc];
            }
        }
        "announcement" | "not_announcement" => {
            msg.message_stub_type = Some(web_message_info::StubType::GroupChangeAnnounce as i32);
            msg.message_stub_parameters = vec![if child.tag == "announcement" {
                "on".to_string()
            } else {
                "off".to_string()
            }];
        }
        "locked" | "unlocked" => {
            msg.message_stub_type = Some(web_message_info::StubType::GroupChangeRestrict as i32);
            msg.message_stub_parameters = vec![if child.tag == "locked" {
                "on".to_string()
            } else {
                "off".to_string()
            }];
        }
        "invite" => {
            msg.message_stub_type = Some(web_message_info::StubType::GroupChangeInviteLink as i32);
            if let Some(code) = child.attrs.get("code") {
                msg.message_stub_parameters = vec![code.clone()];
            }
        }
        "member_add_mode" => {
            if let Some(mode) = match &child.content {
                Some(BinaryNodeData::String(s)) => Some(s.clone()),
                Some(BinaryNodeData::Bytes(b)) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            } {
                msg.message_stub_type = Some(web_message_info::StubType::GroupMemberAddMode as i32);
                msg.message_stub_parameters = vec![mode];
            }
        }
        "membership_approval_mode" => {
            if let Some(group_join) = get_binary_node_child(Some(child), "group_join") {
                if let Some(state) = group_join.attrs.get("state") {
                    msg.message_stub_type =
                        Some(web_message_info::StubType::GroupMembershipJoinApprovalMode as i32);
                    msg.message_stub_parameters = vec![state.clone()];
                }
            }
        }
        "created_membership_requests" => {
            msg.message_stub_type = Some(
                web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd as i32,
            );
            let mut params = vec![
                serde_json::json!({
                    "lid": affected_participant_lid,
                    "pn": affected_participant_pn
                })
                .to_string(),
                "created".to_string(),
            ];
            if let Some(method) = child.attrs.get("request_method") {
                params.push(method.clone());
            }
            msg.message_stub_parameters = params;
        }
        "revoked_membership_requests" => {
            let is_denied = are_jids_same_user(
                affected_participant_lid.as_deref(),
                acting_participant_lid.as_deref(),
            );
            msg.message_stub_type = Some(
                web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd as i32,
            );
            msg.message_stub_parameters = vec![
                serde_json::json!({
                    "lid": affected_participant_lid,
                    "pn": affected_participant_pn
                })
                .to_string(),
                if is_denied {
                    "revoked".to_string()
                } else {
                    "rejected".to_string()
                },
            ];
        }
        _ => {}
    }
}

pub struct MessagesRecvSocket {
    pub messages: Arc<MessagesSocket>,
    retry_counts: AsyncMutex<HashMap<String, u32>>,
    max_msg_retry_count: u32,
    send_active_receipts: AtomicBool,
    events_tx: broadcast::Sender<RecvEvent>,
}

impl MessagesRecvSocket {
    pub fn new(messages: Arc<MessagesSocket>) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            messages,
            retry_counts: AsyncMutex::new(HashMap::new()),
            max_msg_retry_count: DEFAULT_MAX_MSG_RETRY_COUNT,
            send_active_receipts: AtomicBool::new(false),
            events_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RecvEvent> {
        self.events_tx.subscribe()
    }

    pub fn set_send_active_receipts(&self, active: bool) {
        self.send_active_receipts.store(active, Ordering::SeqCst);
    }

    pub async fn send_message_ack(
        &self,
        node: &BinaryNode,
        error_code: Option<u16>,
    ) -> Result<(), MessagesRecvError> {
        let creds = self.messages.socket.creds().await;
        let me_id = creds
            .me
            .as_ref()
            .map(|m| m.id.as_str())
            .unwrap_or("");
        let stanza = build_ack_stanza(node, error_code, me_id);
        self.messages.socket.send_node(&stanza)?;
        Ok(())
    }

    pub async fn reject_call(
        &self,
        call_id: &str,
        call_from: &str,
    ) -> Result<(), MessagesRecvError> {
        let creds = self.messages.socket.creds().await;
        let me_id = creds
            .me
            .as_ref()
            .map(|m| m.id.clone())
            .ok_or(MessagesRecvError::NotAuthenticated)?;

        let stanza = BinaryNode {
            tag: "call".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), me_id),
                ("to".to_string(), call_from.to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "reject".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("call-id".to_string(), call_id.to_string()),
                    ("call-creator".to_string(), call_from.to_string()),
                    ("count".to_string(), "0".to_string()),
                ]),
                content: None,
            }])),
        };
        self.messages.socket.query(stanza, None).await?;
        Ok(())
    }

    pub async fn send_retry_request(
        &self,
        node: &BinaryNode,
        force_include_keys: bool,
    ) -> Result<(), MessagesRecvError> {
        let creds = self.messages.socket.creds().await;
        let me = creds
            .me
            .as_ref()
            .ok_or(MessagesRecvError::NotAuthenticated)?;
        let decoded = decode_message_node(node, &me.id, me.lid.as_deref().unwrap_or(""))?;
        let msg_id = decoded.full_message.key.id.clone().unwrap_or_default();
        let retry_key = format!(
            "{}:{}",
            msg_id,
            decoded
                .full_message
                .key
                .participant
                .as_deref()
                .unwrap_or("")
        );

        let retry_count = {
            let mut counts = self.retry_counts.lock().await;
            let count = counts.get(&retry_key).copied().unwrap_or(0);
            if count >= self.max_msg_retry_count {
                counts.remove(&retry_key);
                return Ok(());
            }
            let next = count + 1;
            counts.insert(retry_key, next);
            next
        };

        let mut receipt_attrs = BinaryNodeAttributes::from([
            ("id".to_string(), msg_id),
            ("type".to_string(), "retry".to_string()),
            (
                "to".to_string(),
                node.attrs.get("from").cloned().unwrap_or_default(),
            ),
        ]);
        if let Some(recipient) = node.attrs.get("recipient") {
            receipt_attrs.insert("recipient".to_string(), recipient.clone());
        }
        if let Some(participant) = node.attrs.get("participant") {
            receipt_attrs.insert("participant".to_string(), participant.clone());
        }

        let mut content = vec![
            BinaryNode {
                tag: "retry".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("count".to_string(), retry_count.to_string()),
                    (
                        "id".to_string(),
                        node.attrs.get("id").cloned().unwrap_or_default(),
                    ),
                    (
                        "t".to_string(),
                        node.attrs.get("t").cloned().unwrap_or_default(),
                    ),
                    ("v".to_string(), "1".to_string()),
                    ("error".to_string(), "0".to_string()),
                ]),
                content: None,
            },
            BinaryNode {
                tag: "registration".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(encode_big_endian(
                    creds.registration_id,
                    4,
                ))),
            },
        ];

        if retry_count > 1 || force_include_keys {
            let next_prekeys = get_next_pre_keys(&self.messages.auth, 1).await?;
            if let Some((&key_id, key_pair)) = next_prekeys.pre_keys.iter().next() {
                let mut keys_children = vec![
                    BinaryNode {
                        tag: "type".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(KEY_BUNDLE_TYPE.to_vec())),
                    },
                    BinaryNode {
                        tag: "identity".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(
                            creds.signed_identity_key.public.clone(),
                        )),
                    },
                    xmpp_pre_key(key_pair, key_id),
                    xmpp_signed_pre_key(&creds.signed_pre_key),
                ];

                if let Some(account_bytes) = &creds.account {
                    if let Ok(account) = AdvSignedDeviceIdentity::decode(account_bytes.as_slice()) {
                        keys_children.push(BinaryNode {
                            tag: "device-identity".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::Bytes(encode_signed_device_identity(
                                &account, true,
                            ))),
                        });
                    }
                }

                content.push(BinaryNode {
                    tag: "keys".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(keys_children)),
                });
            }
        }

        let receipt = BinaryNode {
            tag: "receipt".to_string(),
            attrs: receipt_attrs,
            content: Some(BinaryNodeData::List(content)),
        };

        self.messages.socket.send_node(&receipt)?;
        Ok(())
    }

    pub async fn handle_message(&self, node: &BinaryNode) -> Result<(), MessagesRecvError> {
        if let Some(enc_node) = get_binary_node_child(Some(node), "enc") {
            if enc_node.attrs.get("type").map(|s| s.as_str()) == Some("msmsg") {
                self.send_message_ack(node, Some(NackReason::MissingMessageSecret as u16))
                    .await?;
                return Ok(());
            }
        }

        let creds = self.messages.socket.creds().await;
        let me = creds
            .me
            .as_ref()
            .ok_or(MessagesRecvError::NotAuthenticated)?;
        let me_lid = me.lid.as_deref().unwrap_or("");

        let decoded =
            decrypt_message_node(node, &me.id, me_lid, &self.messages.signal_repository).await?;
        let msg = decoded.full_message;

        if let Some(alt) = msg
            .key
            .participant_alt
            .as_deref()
            .or(msg.key.remote_jid_alt.as_deref())
        {
            if let (Some(alt_decoded), Some(primary)) = (
                jid_decode(alt),
                msg.key
                    .participant
                    .as_deref()
                    .or(msg.key.remote_jid.as_deref()),
            ) {
                if alt_decoded.server.as_str() == "lid" {
                    if self
                        .messages
                        .signal_repository
                        .lid_mapping
                        .get_pn_for_lid(alt)
                        .await
                        .is_none()
                    {
                        let _ = self
                            .messages
                            .signal_repository
                            .lid_mapping
                            .store_lid_pn_mappings(&[LidMapping {
                                lid: alt.to_string(),
                                pn: primary.to_string(),
                            }])
                            .await;
                        let _ = self
                            .messages
                            .signal_repository
                            .migrate_session(primary, alt)
                            .await;
                    }
                } else {
                    let _ = self
                        .messages
                        .signal_repository
                        .lid_mapping
                        .store_lid_pn_mappings(&[LidMapping {
                            lid: primary.to_string(),
                            pn: alt.to_string(),
                        }])
                        .await;
                    let _ = self
                        .messages
                        .signal_repository
                        .migrate_session(alt, primary)
                        .await;
                }
            }
        }

        let is_ciphertext_stub =
            msg.message_stub_type == Some(web_message_info::StubType::Ciphertext as i32);

        if is_ciphertext_stub && msg.category.as_deref() != Some("peer") {
            let first_param = msg.message_stub_parameters.first().map(|s| s.as_str());
            if first_param == Some(MISSING_KEYS_ERROR_TEXT) {
                self.send_message_ack(node, Some(NackReason::ParsingError as u16))
                    .await?;
                return Ok(());
            }
            if first_param == Some(NO_MESSAGE_FOUND_ERROR_TEXT) {
                self.send_message_ack(node, None).await?;
            } else {
                let is_expired_status = msg
                    .key
                    .remote_jid
                    .as_deref()
                    .is_some_and(is_jid_status_broadcast)
                    && unix_timestamp_seconds().saturating_sub(msg.message_timestamp.unwrap_or(0))
                        > u64::from(STATUS_EXPIRY_SECONDS);

                if is_expired_status {
                    self.send_message_ack(node, None).await?;
                    return Ok(());
                }

                let has_enc = get_binary_node_child(Some(node), "enc").is_some();
                let _ = self.send_retry_request(node, !has_enc).await;
                self.send_message_ack(node, Some(NackReason::UnhandledError as u16))
                    .await?;
            }
        } else if let (Some(remote_jid), Some(msg_id)) =
            (msg.key.remote_jid.as_deref(), msg.key.id.as_deref())
        {
            if is_jid_newsletter(Some(remote_jid)) {
                self.send_message_ack(node, None).await?;
            } else {
                let mut receipt_type = MessageReceiptType::Delivery;
                let mut participant = msg.key.participant.as_deref();
                if decoded.category.as_deref() == Some("peer") {
                    receipt_type = MessageReceiptType::PeerMsg;
                } else if msg.key.from_me == Some(true) {
                    receipt_type = MessageReceiptType::Sender;
                    if is_lid_user(Some(remote_jid))
                        || is_lid_user(msg.key.remote_jid_alt.as_deref())
                    {
                        participant = Some(decoded.author.as_str());
                    }
                } else if !self.send_active_receipts.load(Ordering::SeqCst) {
                    receipt_type = MessageReceiptType::Inactive;
                }

                let _ = self.messages.send_receipt(
                    remote_jid,
                    participant,
                    &[msg_id.to_string()],
                    receipt_type,
                );
            }
        }

        let _ = self.events_tx.send(RecvEvent::MessageUpsert {
            message: msg,
            is_offline: node.attrs.contains_key("offline"),
        });

        Ok(())
    }

    pub async fn handle_receipt(&self, node: &BinaryNode) -> Result<(), MessagesRecvError> {
        let creds = self.messages.socket.creds().await;
        let me = creds.me.as_ref();
        let from = node.attrs.get("from").cloned().unwrap_or_default();
        let is_lid = from.contains("lid");
        let my_jid = me.and_then(|m| {
            if is_lid {
                m.lid.as_deref()
            } else {
                Some(m.id.as_str())
            }
        });

        let participant_or_from = node
            .attrs
            .get("participant")
            .map(|s| s.as_str())
            .unwrap_or(from.as_str());
        let is_node_from_me = are_jids_same_user(Some(participant_or_from), my_jid);

        let remote_jid = if !is_node_from_me || is_jid_group(Some(&from)) {
            Some(from.clone())
        } else {
            node.attrs.get("recipient").cloned()
        };

        let receipt_type = node.attrs.get("type").map(|s| s.as_str());
        let from_me = !node.attrs.contains_key("recipient")
            || ((receipt_type == Some("retry") || receipt_type == Some("sender"))
                && is_node_from_me);

        let mut ids = Vec::new();
        if let Some(id) = node.attrs.get("id") {
            ids.push(id.clone());
        }
        if let Some(BinaryNodeData::List(children)) = &node.content {
            if let Some(first) = children.first() {
                for item in get_binary_node_children(Some(first), "item") {
                    if let Some(id) = item.attrs.get("id") {
                        ids.push(id.clone());
                    }
                }
            }
        }

        let timestamp = node.attrs.get("t").and_then(|t| t.parse::<u64>().ok());

        if let Some(status) = get_status_from_receipt_type(receipt_type) {
            if status >= web_message_info::Status::ServerAck as i32 || !is_node_from_me {
                let is_group_or_status = is_jid_group(remote_jid.as_deref())
                    || remote_jid
                        .as_deref()
                        .is_some_and(is_jid_status_broadcast);

                if is_group_or_status {
                    if let Some(participant) = node.attrs.get("participant") {
                        let user_jid = jid_normalized_user(Some(participant));
                        for id in &ids {
                            let _ = self.events_tx.send(RecvEvent::MessageReceiptUpdate {
                                key: WaMessageKey {
                                    remote_jid: remote_jid.clone(),
                                    id: Some(id.clone()),
                                    from_me: Some(from_me),
                                    participant: Some(participant.clone()),
                                    ..Default::default()
                                },
                                user_jid: user_jid.clone(),
                                status,
                                timestamp,
                            });
                        }
                    }
                } else {
                    for id in &ids {
                        let _ = self.events_tx.send(RecvEvent::MessageStatusUpdate {
                            key: WaMessageKey {
                                remote_jid: remote_jid.clone(),
                                id: Some(id.clone()),
                                from_me: Some(from_me),
                                participant: node.attrs.get("participant").cloned(),
                                ..Default::default()
                            },
                            status,
                            timestamp,
                        });
                    }
                }
            }
        }

        if receipt_type == Some("retry") {
            let participant = node
                .attrs
                .get("participant")
                .cloned()
                .unwrap_or_else(|| from.clone());
            if let Some(bundle) = extract_e2e_session_from_retry_receipt(node) {
                let _ = self
                    .messages
                    .signal_repository
                    .inject_e2e_session(&participant, &bundle)
                    .await;
            } else if let Some(received_reg_id) = get_binary_node_child_uint(node, "registration", 4)
            {
                if let Some(info) = self
                    .messages
                    .signal_repository
                    .get_session_info(&participant)
                    .await
                {
                    if info.registration_id != 0 && u64::from(info.registration_id) != received_reg_id
                    {
                        let _ = self
                            .messages
                            .signal_repository
                            .delete_session(&[participant])
                            .await;
                    }
                }
            }
        }

        let _ = self.send_message_ack(node, None).await;
        Ok(())
    }

    pub async fn handle_notification(&self, node: &BinaryNode) -> Result<(), MessagesRecvError> {
        let node_type = node.attrs.get("type").map(|s| s.as_str()).unwrap_or("");
        let child = get_all_binary_node_children(node).first();

        match node_type {
            "w:gp2" => {
                if let Some(child_node) = child {
                    let creds = self.messages.socket.creds().await;
                    let me_id = creds.me.as_ref().map(|m| m.id.as_str());
                    let remote_jid = node.attrs.get("from").cloned();
                    let ctx = extract_addressing_context(node);
                    let from_me = are_jids_same_user(
                        node.attrs
                            .get("participant")
                            .map(|s| s.as_str())
                            .or(remote_jid.as_deref()),
                        me_id,
                    );

                    let mut msg = WaMessage {
                        key: WaMessageKey {
                            remote_jid,
                            from_me: Some(from_me),
                            participant: node.attrs.get("participant").cloned(),
                            participant_alt: ctx.sender_alt,
                            participant_username: node.attrs.get("participant_username").cloned(),
                            addressing_mode: Some(ctx.addressing_mode),
                            id: node.attrs.get("id").cloned(),
                            ..Default::default()
                        },
                        participant: node.attrs.get("participant").cloned(),
                        message_timestamp: node
                            .attrs
                            .get("t")
                            .and_then(|t| t.parse::<u64>().ok()),
                        ..Default::default()
                    };

                    handle_group_notification_node(node, child_node, &mut msg);

                    let _ = self.events_tx.send(RecvEvent::MessageUpsert {
                        message: msg,
                        is_offline: node.attrs.contains_key("offline"),
                    });
                }
            }
            "encrypt" => {
                if node.attrs.get("from").map(|s| s.as_str()) == Some(S_WHATSAPP_NET) {
                    if let Some(count_child) = get_binary_node_child(Some(node), "count") {
                        let count = count_child
                            .attrs
                            .get("value")
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(MIN_PREKEY_COUNT);
                        if count < MIN_PREKEY_COUNT {
                            if let Ok(prekeys_node) =
                                get_next_pre_keys_node(&self.messages.auth, MIN_PREKEY_COUNT as u32)
                                    .await
                            {
                                let _ = self.messages.socket.query(prekeys_node.node, None).await;
                            }
                        }
                    }
                }
            }
            "link_code_companion_reg" => {
                let _ = self.handle_link_code_companion_reg(node).await;
            }
            _ => {}
        }

        let _ = self.send_message_ack(node, None).await;
        Ok(())
    }

    async fn handle_link_code_companion_reg(
        &self,
        node: &BinaryNode,
    ) -> Result<(), MessagesRecvError> {
        let reg_node = get_binary_node_child(Some(node), "link_code_companion_reg")
            .ok_or(MessagesRecvError::InvalidLinkCodeBuffer)?;
        let ref_bytes = get_binary_node_child_buffer(Some(reg_node), "link_code_pairing_ref")
            .ok_or(MessagesRecvError::InvalidLinkCodeBuffer)?;
        let primary_identity_pub =
            get_binary_node_child_buffer(Some(reg_node), "primary_identity_pub")
                .ok_or(MessagesRecvError::InvalidLinkCodeBuffer)?;
        let wrapped_ephemeral = get_binary_node_child_buffer(
            Some(reg_node),
            "link_code_pairing_wrapped_primary_ephemeral_pub",
        )
        .ok_or(MessagesRecvError::InvalidLinkCodeBuffer)?;

        if wrapped_ephemeral.len() < 80 {
            return Err(MessagesRecvError::InvalidLinkCodeBuffer);
        }

        let creds = self.messages.socket.creds().await;
        let pairing_code = creds
            .pairing_code
            .as_deref()
            .ok_or(MessagesRecvError::InvalidLinkCodeBuffer)?;
        let me_id = creds
            .me
            .as_ref()
            .map(|m| m.id.clone())
            .ok_or(MessagesRecvError::NotAuthenticated)?;

        let salt = &wrapped_ephemeral[0..32];
        let iv = &wrapped_ephemeral[32..48];
        let payload = &wrapped_ephemeral[48..80];
        let secret_key = derive_pairing_code_key(pairing_code, salt);
        let code_pairing_pub = aes_decrypt_ctr(payload, &secret_key, iv)?;

        let companion_shared_key = Curve::shared_key(
            &creds.pairing_ephemeral_key_pair.private,
            &code_pairing_pub,
        )?;
        let mut random = [0u8; 32];
        let mut link_code_salt = [0u8; 32];
        let mut encrypt_iv = [0u8; 12];
        OsRng.fill_bytes(&mut random);
        OsRng.fill_bytes(&mut link_code_salt);
        OsRng.fill_bytes(&mut encrypt_iv);

        let expanded = hkdf(
            &companion_shared_key,
            32,
            Some(&link_code_salt),
            b"link_code_pairing_key_bundle_encryption_key",
        )?;

        let mut encrypt_payload = Vec::with_capacity(
            creds.signed_identity_key.public.len() + primary_identity_pub.len() + random.len(),
        );
        encrypt_payload.extend_from_slice(&creds.signed_identity_key.public);
        encrypt_payload.extend_from_slice(primary_identity_pub);
        encrypt_payload.extend_from_slice(&random);

        let encrypted = aes_encrypt_gcm(&encrypt_payload, &expanded, &encrypt_iv, &[])?;
        let mut wrapped_bundle =
            Vec::with_capacity(link_code_salt.len() + encrypt_iv.len() + encrypted.len());
        wrapped_bundle.extend_from_slice(&link_code_salt);
        wrapped_bundle.extend_from_slice(&encrypt_iv);
        wrapped_bundle.extend_from_slice(&encrypted);

        let identity_shared =
            Curve::shared_key(&creds.signed_identity_key.private, primary_identity_pub)?;
        let mut identity_payload = Vec::with_capacity(
            companion_shared_key.len() + identity_shared.len() + random.len(),
        );
        identity_payload.extend_from_slice(&companion_shared_key);
        identity_payload.extend_from_slice(&identity_shared);
        identity_payload.extend_from_slice(&random);
        let _adv_secret_b64 = BASE64.encode(hkdf(&identity_payload, 32, None, b"adv_secret")?);

        let iq = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("to".to_string(), S_WHATSAPP_NET.to_string()),
                ("type".to_string(), "set".to_string()),
                ("id".to_string(), self.messages.socket.generate_message_tag()),
                ("xmlns".to_string(), "md".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "link_code_companion_reg".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("jid".to_string(), me_id),
                    ("stage".to_string(), "companion_finish".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "link_code_pairing_wrapped_key_bundle".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(wrapped_bundle)),
                    },
                    BinaryNode {
                        tag: "companion_identity_public".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(
                            creds.signed_identity_key.public.clone(),
                        )),
                    },
                    BinaryNode {
                        tag: "link_code_pairing_ref".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(ref_bytes.to_vec())),
                    },
                ])),
            }])),
        };

        self.messages.socket.query(iq, None).await?;
        Ok(())
    }

    pub async fn handle_call(&self, node: &BinaryNode) -> Result<(), MessagesRecvError> {
        if let Ok(event) = parse_call_event(node) {
            let _ = self.events_tx.send(RecvEvent::Call(event));
        }
        let _ = self.send_message_ack(node, None).await;
        Ok(())
    }

    pub fn handle_bad_ack(&self, node: &BinaryNode) {
        if let Some(error) = node.attrs.get("error") {
            let key = WaMessageKey {
                remote_jid: node.attrs.get("from").cloned(),
                from_me: Some(true),
                id: node.attrs.get("id").cloned(),
                ..Default::default()
            };
            let _ = (
                error == SERVER_ERROR_MESSAGE_ACCOUNT_RESTRICTION,
                error == SERVER_ERROR_SMAX_INVALID,
            );
            let _ = self.events_tx.send(RecvEvent::BadAck {
                key,
                error: error.clone(),
            });
        }
    }

    pub async fn process_node(&self, node: &BinaryNode) -> Result<(), MessagesRecvError> {
        match node.tag.as_str() {
            "message" => self.handle_message(node).await,
            "receipt" => self.handle_receipt(node).await,
            "notification" => self.handle_notification(node).await,
            "call" => self.handle_call(node).await,
            "ack" if node.attrs.get("class").map(|s| s.as_str()) == Some("message") => {
                self.handle_bad_ack(node);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_status_and_call_parsing() {
        assert_eq!(
            get_status_from_receipt_type(None),
            Some(web_message_info::Status::DeliveryAck as i32)
        );
        assert_eq!(
            get_status_from_receipt_type(Some("read")),
            Some(web_message_info::Status::Read as i32)
        );
        assert_eq!(
            get_status_from_receipt_type(Some("played")),
            Some(web_message_info::Status::Played as i32)
        );

        let call_node = BinaryNode {
            tag: "call".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), "573001111111@s.whatsapp.net".to_string()),
                ("t".to_string(), "1700000000".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "offer".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("call-id".to_string(), "CALL_1".to_string()),
                    (
                        "call-creator".to_string(),
                        "573001111111@s.whatsapp.net".to_string(),
                    ),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "video".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }])),
            }])),
        };

        let event = parse_call_event(&call_node).unwrap();
        assert_eq!(event.id, "CALL_1");
        assert_eq!(event.status, "offer");
        assert!(event.is_video);
        assert!(!event.is_group);
    }

    #[test]
    fn test_group_notification_subject_and_remove() {
        let full_node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), "1203630001@g.us".to_string()),
                (
                    "participant".to_string(),
                    "573001111111@s.whatsapp.net".to_string(),
                ),
            ]),
            content: None,
        };

        let subject_child = BinaryNode {
            tag: "subject".to_string(),
            attrs: BinaryNodeAttributes::from([(
                "subject".to_string(),
                "Nuevo Nombre".to_string(),
            )]),
            content: None,
        };
        let mut msg = WaMessage::default();
        handle_group_notification_node(&full_node, &subject_child, &mut msg);
        assert_eq!(
            msg.message_stub_type,
            Some(web_message_info::StubType::GroupChangeSubject as i32)
        );
        assert_eq!(msg.message_stub_parameters, vec!["Nuevo Nombre"]);

        let self_remove_child = BinaryNode {
            tag: "remove".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "participant".to_string(),
                attrs: BinaryNodeAttributes::from([(
                    "jid".to_string(),
                    "573001111111@s.whatsapp.net".to_string(),
                )]),
                content: None,
            }])),
        };
        let mut leave_msg = WaMessage::default();
        handle_group_notification_node(&full_node, &self_remove_child, &mut leave_msg);
        assert_eq!(
            leave_msg.message_stub_type,
            Some(web_message_info::StubType::GroupParticipantLeave as i32)
        );
    }
}
