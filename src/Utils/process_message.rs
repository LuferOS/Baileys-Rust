use crate::proto::history_sync::HistorySyncType;
use crate::proto::message::{
    protocol_message, EncEventResponseMessage, EventResponseMessage, FutureProofMessage,
    PollUpdateMessage, PollVoteMessage, ProtocolMessage, ReactionMessage,
};
use crate::proto::{
    web_message_info, LidMigrationMappingSyncPayload, Message, MessageContextInfo, MessageKey,
    Reaction, WebMessageInfo,
};
use crate::signal::LibSignalRepository;
use crate::types::{
    AuthenticationCreds, GroupParticipant, LidMapping, WaMessage, WaMessageKey,
};
use crate::utils::crypto::{aes_decrypt_gcm, hmac_sign, CryptoError, HmacVariant};
use crate::utils::generics::get_key_author;
use crate::utils::history::{
    download_and_process_history_sync_notification, HistoryChat, HistoryError, ProcessedHistory,
};
use crate::utils::messages::{get_content_type, normalize_message_content};
use crate::utils::messages_media::MediaDownloadOptions;
use crate::utils::tc_token_utils::{
    build_merged_tc_token_index_write, resolve_tc_token_jid, TcTokenEntry,
};
use crate::utils::use_multi_file_auth_state::MultiFileAuthState;
use crate::wa_binary::{
    are_jids_same_user, is_hosted_lid_user, is_hosted_pn_user, is_jid_broadcast,
    is_jid_status_broadcast, is_lid_user, jid_decode, jid_encode, jid_normalized_user, JidServer,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prost::Message as ProstMessage;
use serde_json::Value;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessMessageError {
    #[error("cannot derive chat id: message key is missing remote_jid")]
    MissingRemoteJid,
    #[error("cannot derive chat id: broadcast message key is missing participant")]
    MissingBroadcastParticipant,
    #[error("not authenticated: missing own jid")]
    NotAuthenticated,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("history error: {0}")]
    History(#[from] HistoryError),
}

#[derive(Debug, Clone)]
pub struct PollDecryptContext<'a> {
    pub poll_creator_jid: &'a str,
    pub poll_msg_id: &'a str,
    pub poll_enc_key: &'a [u8],
    pub voter_jid: &'a str,
}

#[derive(Debug, Clone)]
pub struct EventDecryptContext<'a> {
    pub event_creator_jid: &'a str,
    pub event_msg_id: &'a str,
    pub event_enc_key: &'a [u8],
    pub responder_jid: &'a str,
}

#[derive(Debug, Clone, Default)]
pub struct ChatUpdateDelta {
    pub id: String,
    pub messages: Vec<WaMessage>,
    pub conversation_timestamp: Option<u64>,
    pub unread_count: Option<u32>,
    pub archived: Option<bool>,
    pub read_only: Option<bool>,
    pub ephemeral_setting_timestamp: Option<u64>,
    pub ephemeral_expiration: Option<Option<u32>>,
    pub name: Option<String>,
    pub description: Option<String>,
}

impl ChatUpdateDelta {
    pub fn has_changes(&self) -> bool {
        !self.messages.is_empty()
            || self.conversation_timestamp.is_some()
            || self.unread_count.is_some()
            || self.archived.is_some()
            || self.read_only.is_some()
            || self.ephemeral_setting_timestamp.is_some()
            || self.ephemeral_expiration.is_some()
            || self.name.is_some()
            || self.description.is_some()
    }
}

#[derive(Debug, Clone, Default)]
pub struct GroupMetadataPatch {
    pub id: String,
    pub author: Option<String>,
    pub author_pn: Option<String>,
    pub author_username: Option<String>,
    pub announce: Option<bool>,
    pub restrict: Option<bool>,
    pub subject: Option<String>,
    pub desc: Option<String>,
    pub invite_code: Option<String>,
    pub member_add_mode: Option<bool>,
    pub join_approval_mode: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DecryptedEventResponseUpdate {
    pub creation_msg_key: WaMessageKey,
    pub response_msg_key: WaMessageKey,
    pub sender_timestamp_ms: Option<i64>,
    pub response: EventResponseMessage,
}

#[derive(Debug, Clone)]
pub enum ProcessMessageEvent {
    ChatUpdate(ChatUpdateDelta),
    CredsAppStateKeyUpdate(String),
    CredsProcessedHistory {
        key: WaMessageKey,
        message_timestamp: Option<u64>,
    },
    MessagingHistorySet {
        data: ProcessedHistory,
        is_latest: Option<bool>,
        chunk_order: Option<u32>,
        peer_data_request_session_id: Option<String>,
    },
    MessageRevoke {
        key: WaMessageKey,
        protocol_key: WaMessageKey,
    },
    MessageEdit {
        key: WaMessageKey,
        edited_message: Message,
        message_timestamp: Option<u64>,
    },
    MessageUpsert {
        message: WaMessage,
        request_id: Option<String>,
    },
    MessageReaction {
        key: WaMessageKey,
        reaction: Reaction,
    },
    EventResponseUpdate(DecryptedEventResponseUpdate),
    GroupMemberTagUpdate {
        group_id: String,
        label: String,
        participant: Option<String>,
        participant_alt: Option<String>,
        message_timestamp: Option<u64>,
    },
    GroupParticipantsUpdate {
        id: String,
        author: Option<String>,
        author_pn: Option<String>,
        author_username: Option<String>,
        participants: Vec<GroupParticipant>,
        action: String,
    },
    GroupUpdate(GroupMetadataPatch),
    GroupJoinRequest {
        id: String,
        author: Option<String>,
        author_pn: Option<String>,
        author_username: Option<String>,
        participant: String,
        participant_pn: String,
        action: String,
        method: Option<String>,
    },
}

#[derive(Default)]
pub struct PlaceholderResendCache {
    entries: Mutex<HashMap<String, Option<WaMessage>>>,
}

impl PlaceholderResendCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, msg_id: String, msg: Option<WaMessage>) {
        self.entries.lock().unwrap().insert(msg_id, msg);
    }

    pub fn take(&self, msg_id: &str) -> Option<Option<WaMessage>> {
        self.entries.lock().unwrap().remove(msg_id)
    }

    pub fn contains(&self, msg_id: &str) -> bool {
        self.entries.lock().unwrap().contains_key(msg_id)
    }
}

fn is_real_msg_stub_type(stub: i32) -> bool {
    stub == web_message_info::StubType::CallMissedGroupVideo as i32
        || stub == web_message_info::StubType::CallMissedGroupVoice as i32
        || stub == web_message_info::StubType::CallMissedVideo as i32
        || stub == web_message_info::StubType::CallMissedVoice as i32
        || stub == web_message_info::StubType::GroupParticipantAdd as i32
}

fn is_self_only_protocol_type(proto_type: i32) -> bool {
    proto_type == protocol_message::Type::HistorySyncNotification as i32
        || proto_type == protocol_message::Type::AppStateSyncKeyShare as i32
        || proto_type == protocol_message::Type::LidMigrationMappingSync as i32
        || proto_type == protocol_message::Type::PeerDataOperationRequestResponseMessage as i32
}

fn unwrap_future_proof_mut<'a>(mut current: &'a mut Message) -> &'a mut Message {
    for _ in 0..5 {
        let next = if let Some(ref mut w) = current.ephemeral_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.view_once_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.document_with_caption_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.view_once_message_v2 {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.view_once_message_v2_extension {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.edited_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.associated_child_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.group_status_message {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else if let Some(ref mut w) = current.group_status_message_v2 {
            let f: &mut FutureProofMessage = BorrowMut::borrow_mut(w);
            f.message.as_mut().map(|m| BorrowMut::borrow_mut(m))
        } else {
            None
        };

        if let Some(inner) = next {
            current = inner;
        } else {
            break;
        }
    }
    current
}

fn normalise_jid_preserving_hosted(jid: Option<&str>) -> Option<String> {
    let raw = jid.filter(|s| !s.is_empty())?;
    if is_hosted_pn_user(Some(raw)) || is_hosted_lid_user(Some(raw)) {
        let user = jid_decode(raw).map(|d| d.user)?;
        let server = if is_hosted_pn_user(Some(raw)) {
            JidServer::SWhatsappNet
        } else {
            JidServer::Lid
        };
        Some(jid_encode(Some(&user), &server, None, None))
    } else {
        Some(jid_normalized_user(Some(raw)))
    }
}

fn normalise_proto_key(
    msg_key: &mut MessageKey,
    parent_key: &WaMessageKey,
    me_id: &str,
    me_lid: &str,
) {
    if parent_key.from_me != Some(true) {
        let target_jid = msg_key
            .participant
            .as_deref()
            .or(msg_key.remote_jid.as_deref());
        let next_from_me = if msg_key.from_me != Some(true) {
            are_jids_same_user(target_jid, Some(me_id))
                || (!me_lid.is_empty() && are_jids_same_user(target_jid, Some(me_lid)))
        } else {
            false
        };
        msg_key.from_me = Some(next_from_me);
        msg_key.remote_jid = parent_key.remote_jid.clone();
        if msg_key.participant.is_none() {
            msg_key.participant = parent_key.participant.clone();
        }
    }
}

pub fn clean_message(message: &mut WaMessage, me_id: &str, me_lid: &str) {
    message.key.remote_jid = normalise_jid_preserving_hosted(message.key.remote_jid.as_deref());
    message.key.participant = normalise_jid_preserving_hosted(message.key.participant.as_deref());

    let parent_key = message.key.clone();
    if let Some(ref mut proto_msg) = message.message {
        let content = unwrap_future_proof_mut(proto_msg);
        if let Some(ref mut react) = content.reaction_message {
            let inner: &mut ReactionMessage = BorrowMut::borrow_mut(react);
            if let Some(ref mut k) = inner.key {
                normalise_proto_key(k, &parent_key, me_id, me_lid);
            }
        }
        if let Some(ref mut poll_upd) = content.poll_update_message {
            let inner: &mut PollUpdateMessage = BorrowMut::borrow_mut(poll_upd);
            if let Some(ref mut k) = inner.poll_creation_message_key {
                normalise_proto_key(k, &parent_key, me_id, me_lid);
            }
        }
    }
}

pub fn is_real_message(message: &WaMessage) -> bool {
    let normalized = message.message.as_ref().map(normalize_message_content);
    let has_some_content = normalized
        .as_ref()
        .and_then(get_content_type)
        .is_some();
    let stub_is_real = message
        .message_stub_type
        .is_some_and(is_real_msg_stub_type);

    (normalized.is_some() || stub_is_real)
        && has_some_content
        && normalized
            .as_ref()
            .is_none_or(|c| {
                c.protocol_message.is_none()
                    && c.reaction_message.is_none()
                    && c.poll_update_message.is_none()
            })
}

pub fn should_increment_chat_unread(message: &WaMessage) -> bool {
    message.key.from_me != Some(true) && message.message_stub_type.is_none()
}

pub fn get_chat_id(key: &WaMessageKey) -> Result<String, ProcessMessageError> {
    let remote_jid = key
        .remote_jid
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(ProcessMessageError::MissingRemoteJid)?;

    if is_jid_broadcast(Some(remote_jid))
        && !is_jid_status_broadcast(remote_jid)
        && key.from_me != Some(true)
    {
        let participant = key
            .participant
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or(ProcessMessageError::MissingBroadcastParticipant)?;
        return Ok(participant.to_string());
    }

    Ok(remote_jid.to_string())
}

pub fn decrypt_poll_vote(
    enc_payload: &[u8],
    enc_iv: &[u8],
    ctx: &PollDecryptContext<'_>,
) -> Result<PollVoteMessage, ProcessMessageError> {
    let mut sign = Vec::new();
    sign.extend_from_slice(ctx.poll_msg_id.as_bytes());
    sign.extend_from_slice(ctx.poll_creator_jid.as_bytes());
    sign.extend_from_slice(ctx.voter_jid.as_bytes());
    sign.extend_from_slice(b"Poll Vote");
    sign.push(1);

    let key0 = hmac_sign(ctx.poll_enc_key, &[0u8; 32], HmacVariant::Sha256)?;
    let dec_key = hmac_sign(&sign, &key0, HmacVariant::Sha256)?;
    let aad = format!("{}\0{}", ctx.poll_msg_id, ctx.voter_jid);

    let decrypted = aes_decrypt_gcm(enc_payload, &dec_key, enc_iv, aad.as_bytes())?;
    Ok(PollVoteMessage::decode(decrypted.as_slice())?)
}

pub fn decrypt_event_response(
    enc_payload: &[u8],
    enc_iv: &[u8],
    ctx: &EventDecryptContext<'_>,
) -> Result<EventResponseMessage, ProcessMessageError> {
    let mut sign = Vec::new();
    sign.extend_from_slice(ctx.event_msg_id.as_bytes());
    sign.extend_from_slice(ctx.event_creator_jid.as_bytes());
    sign.extend_from_slice(ctx.responder_jid.as_bytes());
    sign.extend_from_slice(b"Event Response");
    sign.push(1);

    let key0 = hmac_sign(ctx.event_enc_key, &[0u8; 32], HmacVariant::Sha256)?;
    let dec_key = hmac_sign(&sign, &key0, HmacVariant::Sha256)?;
    let aad = format!("{}\0{}", ctx.event_msg_id, ctx.responder_jid);

    let decrypted = aes_decrypt_gcm(enc_payload, &dec_key, enc_iv, aad.as_bytes())?;
    Ok(EventResponseMessage::decode(decrypted.as_slice())?)
}

pub async fn store_tc_tokens_from_history_sync(
    chats: &[HistoryChat],
    signal_repository: &LibSignalRepository,
    auth: &MultiFileAuthState,
) {
    struct Candidate {
        storage_jid: String,
        token: Vec<u8>,
        ts: u64,
        sender_ts: Option<u64>,
    }

    let mut candidates = Vec::new();
    for chat in chats {
        let conv = &chat.conversation;
        let ts = conv.tc_token_timestamp.map(|v| v as u64).unwrap_or(0);
        if let Some(ref tok) = conv.tc_token {
            if !tok.is_empty() && ts > 0 {
                let jid = jid_normalized_user(Some(&conv.id));
                let storage_jid =
                    resolve_tc_token_jid(&jid, &signal_repository.lid_mapping).await;
                candidates.push(Candidate {
                    storage_jid,
                    token: tok.clone(),
                    ts,
                    sender_ts: conv.tc_token_sender_timestamp.map(|v| v as u64),
                });
            }
        }
    }

    if candidates.is_empty() {
        return;
    }

    let jids: Vec<String> = candidates.iter().map(|c| c.storage_jid.clone()).collect();
    let existing = auth.get_keys("tctoken", &jids).await;
    let mut entries: HashMap<String, Option<Value>> = HashMap::new();
    let mut stored_jids = Vec::new();

    for c in candidates {
        let existing_entry = existing
            .get(&c.storage_jid)
            .and_then(|v| v.as_ref())
            .and_then(|v| serde_json::from_value::<TcTokenEntry>(v.clone()).ok());
        let existing_ts = existing_entry
            .as_ref()
            .and_then(|e| e.timestamp.as_deref())
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0);

        if existing_ts > 0 && existing_ts >= c.ts {
            continue;
        }

        let updated = TcTokenEntry {
            token: c.token,
            timestamp: Some(c.ts.to_string()),
            sender_timestamp: c
                .sender_ts
                .or_else(|| existing_entry.and_then(|e| e.sender_timestamp)),
        };

        if let Ok(val) = serde_json::to_value(updated) {
            entries.insert(c.storage_jid.clone(), Some(val));
            stored_jids.push(c.storage_jid);
        }
    }

    if !entries.is_empty() {
        if let Ok(index_write) = build_merged_tc_token_index_write(auth, &stored_jids).await {
            entries.extend(index_write);
        }
        let mut batch = HashMap::new();
        batch.insert("tctoken".to_string(), entries);
        let _ = auth.set_keys(batch).await;
    }
}

fn wa_message_from_web_message_info(info: WebMessageInfo) -> WaMessage {
    let key = info
        .key
        .as_ref()
        .map(WaMessageKey::from_proto)
        .unwrap_or_default();
    WaMessage {
        key,
        message_timestamp: info.message_timestamp,
        push_name: info.push_name,
        broadcast: info.broadcast,
        status: info.status,
        participant: info.participant,
        verified_biz_name: info.verified_biz_name,
        message: info.message,
        message_stub_type: info.message_stub_type,
        message_stub_parameters: info.message_stub_parameters,
        user_receipt: info.user_receipt,
        reactions: info.reactions,
        poll_updates: info.poll_updates,
        ..Default::default()
    }
}

fn parse_stub_participants(params: &[String]) -> Vec<GroupParticipant> {
    params
        .iter()
        .filter_map(|raw| {
            let val: Value = serde_json::from_str(raw).ok()?;
            let id = val.get("id")?.as_str()?.to_string();
            Some(GroupParticipant {
                id,
                phone_number: val
                    .get("phoneNumber")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                lid: val.get("lid").and_then(|v| v.as_str()).map(String::from),
                username: val
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                admin: val.get("admin").and_then(|v| v.as_str()).map(String::from),
            })
        })
        .collect()
}

pub async fn process_message<G, GFut>(
    message: &WaMessage,
    should_process_history_msg: bool,
    placeholder_resend_cache: Option<&PlaceholderResendCache>,
    creds: &AuthenticationCreds,
    signal_repository: &LibSignalRepository,
    auth: &MultiFileAuthState,
    download_opts: &MediaDownloadOptions,
    mut get_message: G,
) -> Result<Vec<ProcessMessageEvent>, ProcessMessageError>
where
    G: FnMut(WaMessageKey) -> GFut,
    GFut: Future<Output = Option<Message>>,
{
    let me_id = creds
        .me
        .as_ref()
        .map(|m| m.id.as_str())
        .ok_or(ProcessMessageError::NotAuthenticated)?;
    let unarchive_chats = creds.account_settings.unarchive_chats;

    let mut events = Vec::new();
    let chat_id = jid_normalized_user(Some(&get_chat_id(&message.key)?));
    let mut chat = ChatUpdateDelta {
        id: chat_id.clone(),
        ..Default::default()
    };

    let is_real_msg = is_real_message(message);
    if is_real_msg {
        chat.messages.push(message.clone());
        chat.conversation_timestamp = message.message_timestamp;
        if should_increment_chat_unread(message) {
            chat.unread_count = Some(1);
        }
    }

    let content = message.message.as_ref().map(normalize_message_content);

    let reaction_from_me = content
        .as_ref()
        .and_then(|c| c.reaction_message.as_ref())
        .and_then(|r| {
            let inner: &ReactionMessage = Borrow::borrow(r);
            inner.key.as_ref()?.from_me
        })
        == Some(true);

    if (is_real_msg || reaction_from_me) && unarchive_chats {
        chat.archived = Some(false);
        chat.read_only = Some(false);
    }

    if let Some(proto_msg_box) = content.as_ref().and_then(|c| c.protocol_message.as_ref()) {
        let protocol_msg: &ProtocolMessage = Borrow::borrow(proto_msg_box);
        if let Some(proto_type) = protocol_msg.r#type {
            if is_self_only_protocol_type(proto_type) && message.key.from_me != Some(true) {
                return Ok(events);
            }

            if proto_type == protocol_message::Type::HistorySyncNotification as i32 {
                if should_process_history_msg {
                    if let Some(hist_notif_box) = protocol_msg.history_sync_notification.as_ref() {
                        let hist_notif = Borrow::borrow(hist_notif_box);
                        let is_latest = creds.processed_history_messages.is_empty();
                        let is_on_demand =
                            hist_notif.sync_type == Some(HistorySyncType::OnDemand as i32);

                        if !is_on_demand {
                            events.push(ProcessMessageEvent::CredsProcessedHistory {
                                key: message.key.clone(),
                                message_timestamp: message.message_timestamp,
                            });
                        }

                        let data = download_and_process_history_sync_notification(
                            hist_notif,
                            download_opts,
                        )
                        .await?;

                        if !data.lid_pn_mappings.is_empty() {
                            let _ = signal_repository
                                .lid_mapping
                                .store_lid_pn_mappings(&data.lid_pn_mappings)
                                .await;
                        }

                        store_tc_tokens_from_history_sync(&data.chats, signal_repository, auth)
                            .await;

                        events.push(ProcessMessageEvent::MessagingHistorySet {
                            data,
                            is_latest: if is_on_demand { None } else { Some(is_latest) },
                            chunk_order: hist_notif.chunk_order,
                            peer_data_request_session_id: hist_notif
                                .peer_data_request_session_id
                                .clone(),
                        });
                    }
                }
            } else if proto_type == protocol_message::Type::AppStateSyncKeyShare as i32 {
                if let Some(ref share) = protocol_msg.app_state_sync_key_share {
                    if !share.keys.is_empty() {
                        let mut new_app_state_key_id = String::new();
                        let mut key_entries: HashMap<String, Option<Value>> = HashMap::new();
                        for item in &share.keys {
                            if let (Some(key_id_bytes), Some(key_data)) = (
                                item.key_id.as_ref().and_then(|k| k.key_id.as_deref()),
                                item.key_data.as_ref(),
                            ) {
                                let str_key_id = BASE64.encode(key_id_bytes);
                                let encoded_bytes = key_data.encode_to_vec();
                                key_entries.insert(
                                    str_key_id.clone(),
                                    Some(Value::String(BASE64.encode(encoded_bytes))),
                                );
                                new_app_state_key_id = str_key_id;
                            }
                        }
                        if !key_entries.is_empty() {
                            let mut batch = HashMap::new();
                            batch.insert("app-state-sync-key".to_string(), key_entries);
                            let _ = auth.set_keys(batch).await;
                            events.push(ProcessMessageEvent::CredsAppStateKeyUpdate(
                                new_app_state_key_id,
                            ));
                        }
                    }
                }
            } else if proto_type == protocol_message::Type::Revoke as i32 {
                let mut target_key = message.key.clone();
                if let Some(ref pk) = protocol_msg.key {
                    target_key.id = pk.id.clone();
                }
                events.push(ProcessMessageEvent::MessageRevoke {
                    key: target_key,
                    protocol_key: message.key.clone(),
                });
            } else if proto_type == protocol_message::Type::EphemeralSetting as i32 {
                chat.ephemeral_setting_timestamp = message.message_timestamp;
                chat.ephemeral_expiration = Some(protocol_msg.ephemeral_expiration.filter(|&e| e > 0));
            } else if proto_type
                == protocol_message::Type::PeerDataOperationRequestResponseMessage as i32
            {
                if let Some(ref resp) = protocol_msg.peer_data_operation_request_response_message {
                    for res in &resp.peer_data_operation_result {
                        let Some(bytes) = res
                            .placeholder_message_resend_response
                            .as_ref()
                            .and_then(|r| r.web_message_info_bytes.as_deref())
                        else {
                            continue;
                        };
                        if let Ok(web_info) = WebMessageInfo::decode(bytes) {
                            let msg_id = web_info.key.as_ref().and_then(|k| k.id.clone());
                            let cached = msg_id
                                .as_deref()
                                .and_then(|id| placeholder_resend_cache.and_then(|c| c.take(id)))
                                .flatten();

                            let final_msg = if let Some(mut cached_msg) = cached {
                                cached_msg.message = web_info.message;
                                if web_info.message_timestamp.is_some() {
                                    cached_msg.message_timestamp = web_info.message_timestamp;
                                }
                                cached_msg
                            } else {
                                wa_message_from_web_message_info(web_info)
                            };

                            events.push(ProcessMessageEvent::MessageUpsert {
                                message: final_msg,
                                request_id: resp.stanza_id.clone(),
                            });
                        }
                    }
                }
            } else if proto_type == protocol_message::Type::MessageEdit as i32 {
                if let Some(ref edited_box) = protocol_msg.edited_message {
                    let edited_ref: &Message = Borrow::borrow(edited_box);
                    let mut target_key = message.key.clone();
                    if let Some(ref pk) = protocol_msg.key {
                        target_key.id = pk.id.clone();
                    }
                    let ts = protocol_msg
                        .timestamp_ms
                        .map(|ms| (ms as u64) / 1000)
                        .or(message.message_timestamp);
                    events.push(ProcessMessageEvent::MessageEdit {
                        key: target_key,
                        edited_message: edited_ref.clone(),
                        message_timestamp: ts,
                    });
                }
            } else if proto_type == protocol_message::Type::GroupMemberLabelChange as i32 {
                if let Some(label) = protocol_msg
                    .member_label
                    .as_ref()
                    .and_then(|m| m.label.as_deref())
                    .filter(|s| !s.is_empty())
                {
                    events.push(ProcessMessageEvent::GroupMemberTagUpdate {
                        group_id: chat_id.clone(),
                        label: label.to_string(),
                        participant: message.key.participant.clone(),
                        participant_alt: message.key.participant_alt.clone(),
                        message_timestamp: message.message_timestamp,
                    });
                }
            } else if proto_type == protocol_message::Type::LidMigrationMappingSync as i32 {
                if let Some(payload) = protocol_msg
                    .lid_migration_mapping_sync_message
                    .as_ref()
                    .and_then(|m| m.encoded_mapping_payload.as_deref())
                {
                    if let Ok(decoded) = LidMigrationMappingSyncPayload::decode(payload) {
                        let mut pairs = Vec::new();
                        for mapping in &decoded.pn_to_lid_mappings {
                            let pn = mapping.pn.as_ref().map(|v| v.to_string());
                            let lid = mapping
                                .latest_lid
                                .as_ref()
                                .or(mapping.assigned_lid.as_ref())
                                .map(|v| v.to_string());
                            if let (Some(pn_s), Some(lid_s)) = (pn, lid) {
                                pairs.push(LidMapping {
                                    lid: format!("{}@lid", lid_s),
                                    pn: format!("{}@s.whatsapp.net", pn_s),
                                });
                            }
                        }
                        if !pairs.is_empty() {
                            let _ = signal_repository
                                .lid_mapping
                                .store_lid_pn_mappings(&pairs)
                                .await;
                            for pair in &pairs {
                                let _ = signal_repository
                                    .migrate_session(&pair.pn, &pair.lid)
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    } else if let Some(react_box) = content.as_ref().and_then(|c| c.reaction_message.as_ref()) {
        let react_msg: &ReactionMessage = Borrow::borrow(react_box);
        if let Some(ref target_proto_key) = react_msg.key {
            let reaction = Reaction {
                key: Some(message.key.to_proto()),
                text: react_msg.text.clone(),
                grouping_key: react_msg.grouping_key.clone(),
                sender_timestamp_ms: react_msg.sender_timestamp_ms,
                unread: None,
            };
            events.push(ProcessMessageEvent::MessageReaction {
                key: WaMessageKey::from_proto(target_proto_key),
                reaction,
            });
        }
    } else if let Some(enc_event_box) = content
        .as_ref()
        .and_then(|c| c.enc_event_response_message.as_ref())
    {
        let enc_event: &EncEventResponseMessage = Borrow::borrow(enc_event_box);
        if let Some(ref creation_proto_key) = enc_event.event_creation_message_key {
            let creation_key = WaMessageKey::from_proto(creation_proto_key);
            if let Some(event_msg) = get_message(creation_key.clone()).await {
                let enc_key = event_msg
                    .message_context_info
                    .as_ref()
                    .and_then(|m| {
                        let inner: &MessageContextInfo = Borrow::borrow(m);
                        inner.message_secret.as_deref()
                    });
                if let (Some(event_enc_key), Some(enc_payload), Some(enc_iv), Some(event_msg_id)) = (
                    enc_key,
                    enc_event.enc_payload.as_deref(),
                    enc_event.enc_iv.as_deref(),
                    creation_key.id.as_deref(),
                ) {
                    let me_norm = jid_normalized_user(Some(me_id));
                    let creator_raw = creation_key
                        .participant
                        .as_deref()
                        .or(creation_key.remote_jid.as_deref())
                        .unwrap_or("");
                    let creator_pn = if is_lid_user(Some(creator_raw)) {
                        signal_repository
                            .lid_mapping
                            .get_pn_for_lid(creator_raw)
                            .await
                            .unwrap_or_else(|| creator_raw.to_string())
                    } else {
                        creator_raw.to_string()
                    };
                    let creator_norm = jid_normalized_user(Some(&creator_pn));
                    let creator_key = WaMessageKey {
                        remote_jid: Some(creator_norm.clone()),
                        from_me: Some(me_norm == creator_pn),
                        ..Default::default()
                    };
                    let event_creator_jid = get_key_author(Some(&creator_key), Some(&me_norm));
                    let responder_jid = get_key_author(Some(&message.key), Some(&me_norm));

                    if let Ok(response_msg) = decrypt_event_response(
                        enc_payload,
                        enc_iv,
                        &EventDecryptContext {
                            event_creator_jid: &event_creator_jid,
                            event_msg_id,
                            event_enc_key,
                            responder_jid: &responder_jid,
                        },
                    ) {
                        events.push(ProcessMessageEvent::EventResponseUpdate(
                            DecryptedEventResponseUpdate {
                                creation_msg_key: creation_key,
                                response_msg_key: message.key.clone(),
                                sender_timestamp_ms: response_msg.timestamp_ms,
                                response: response_msg,
                            },
                        ));
                    }
                }
            }
        }
    } else if let Some(stub_type) = message.message_stub_type {
        let jid = message.key.remote_jid.clone().unwrap_or_default();
        let make_group_patch = || GroupMetadataPatch {
            id: jid.clone(),
            author: message.key.participant.clone(),
            author_pn: message.key.participant_alt.clone(),
            author_username: message.key.participant_username.clone(),
            ..Default::default()
        };

        let participants_includes_me = |list: &[GroupParticipant]| {
            list.iter()
                .any(|p| are_jids_same_user(Some(me_id), p.phone_number.as_deref()))
        };

        if stub_type == web_message_info::StubType::GroupParticipantChangeNumber as i32 {
            let participants = parse_stub_participants(&message.message_stub_parameters);
            events.push(ProcessMessageEvent::GroupParticipantsUpdate {
                id: jid,
                author: message.key.participant.clone(),
                author_pn: message.key.participant_alt.clone(),
                author_username: message.key.participant_username.clone(),
                participants,
                action: "modify".to_string(),
            });
        } else if stub_type == web_message_info::StubType::GroupParticipantLeave as i32
            || stub_type == web_message_info::StubType::GroupParticipantRemove as i32
        {
            let participants = parse_stub_participants(&message.message_stub_parameters);
            if participants_includes_me(&participants) {
                chat.read_only = Some(true);
            }
            events.push(ProcessMessageEvent::GroupParticipantsUpdate {
                id: jid,
                author: message.key.participant.clone(),
                author_pn: message.key.participant_alt.clone(),
                author_username: message.key.participant_username.clone(),
                participants,
                action: "remove".to_string(),
            });
        } else if stub_type == web_message_info::StubType::GroupParticipantAdd as i32
            || stub_type == web_message_info::StubType::GroupParticipantInvite as i32
            || stub_type == web_message_info::StubType::GroupParticipantAddRequestJoin as i32
        {
            let participants = parse_stub_participants(&message.message_stub_parameters);
            if participants_includes_me(&participants) {
                chat.read_only = Some(false);
            }
            events.push(ProcessMessageEvent::GroupParticipantsUpdate {
                id: jid,
                author: message.key.participant.clone(),
                author_pn: message.key.participant_alt.clone(),
                author_username: message.key.participant_username.clone(),
                participants,
                action: "add".to_string(),
            });
        } else if stub_type == web_message_info::StubType::GroupParticipantDemote as i32 {
            let participants = parse_stub_participants(&message.message_stub_parameters);
            events.push(ProcessMessageEvent::GroupParticipantsUpdate {
                id: jid,
                author: message.key.participant.clone(),
                author_pn: message.key.participant_alt.clone(),
                author_username: message.key.participant_username.clone(),
                participants,
                action: "demote".to_string(),
            });
        } else if stub_type == web_message_info::StubType::GroupParticipantPromote as i32 {
            let participants = parse_stub_participants(&message.message_stub_parameters);
            events.push(ProcessMessageEvent::GroupParticipantsUpdate {
                id: jid,
                author: message.key.participant.clone(),
                author_pn: message.key.participant_alt.clone(),
                author_username: message.key.participant_username.clone(),
                participants,
                action: "promote".to_string(),
            });
        } else if stub_type == web_message_info::StubType::GroupChangeAnnounce as i32 {
            let val = message.message_stub_parameters.first().map(|s| s.as_str());
            let mut patch = make_group_patch();
            patch.announce = Some(val == Some("true") || val == Some("on"));
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupChangeRestrict as i32 {
            let val = message.message_stub_parameters.first().map(|s| s.as_str());
            let mut patch = make_group_patch();
            patch.restrict = Some(val == Some("true") || val == Some("on"));
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupChangeSubject as i32 {
            let name = message.message_stub_parameters.first().cloned();
            chat.name = name.clone();
            let mut patch = make_group_patch();
            patch.subject = name;
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupChangeDescription as i32 {
            let desc = message.message_stub_parameters.first().cloned();
            chat.description = desc.clone();
            let mut patch = make_group_patch();
            patch.desc = desc;
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupChangeInviteLink as i32 {
            let mut patch = make_group_patch();
            patch.invite_code = message.message_stub_parameters.first().cloned();
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupMemberAddMode as i32 {
            let val = message.message_stub_parameters.first().map(|s| s.as_str());
            let mut patch = make_group_patch();
            patch.member_add_mode = Some(val == Some("all_member_add"));
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type == web_message_info::StubType::GroupMembershipJoinApprovalMode as i32 {
            let val = message.message_stub_parameters.first().map(|s| s.as_str());
            let mut patch = make_group_patch();
            patch.join_approval_mode = Some(val == Some("on"));
            events.push(ProcessMessageEvent::GroupUpdate(patch));
        } else if stub_type
            == web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd as i32
        {
            if let Some(raw_part) = message.message_stub_parameters.first() {
                if let Ok(mapping) = serde_json::from_str::<LidMapping>(raw_part) {
                    let action = message
                        .message_stub_parameters
                        .get(1)
                        .cloned()
                        .unwrap_or_default();
                    let method = message.message_stub_parameters.get(2).cloned();
                    events.push(ProcessMessageEvent::GroupJoinRequest {
                        id: jid,
                        author: message.key.participant.clone(),
                        author_pn: message.key.participant_alt.clone(),
                        author_username: message.key.participant_username.clone(),
                        participant: mapping.lid,
                        participant_pn: mapping.pn,
                        action,
                        method,
                    });
                }
            }
        }
    }

    if chat.has_changes() {
        events.push(ProcessMessageEvent::ChatUpdate(chat));
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{init_auth_creds, ContactInfo};
    use crate::utils::crypto::aes_encrypt_gcm;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;
    use std::sync::Arc;

    #[test]
    fn test_clean_message_and_chat_id() {
        let mut msg = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573001111111:3@s.whatsapp.net".to_string()),
                from_me: Some(false),
                id: Some("M1".to_string()),
                ..Default::default()
            },
            message: Some(Message {
                reaction_message: Some(
                    ReactionMessage {
                        key: Some(MessageKey {
                            remote_jid: Some("573002222222@s.whatsapp.net".to_string()),
                            from_me: Some(false),
                            id: Some("TARGET1".to_string()),
                            participant: None,
                        }),
                        text: Some("🔥".to_string()),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        clean_message(&mut msg, "573002222222:1@s.whatsapp.net", "222@lid");
        assert_eq!(
            msg.key.remote_jid.as_deref(),
            Some("573001111111@s.whatsapp.net")
        );
        let react: &ReactionMessage =
            Borrow::borrow(msg.message.as_ref().unwrap().reaction_message.as_ref().unwrap());
        let react_key = react.key.as_ref().unwrap();
        assert_eq!(react_key.from_me, Some(true));
        assert_eq!(
            react_key.remote_jid.as_deref(),
            Some("573001111111@s.whatsapp.net")
        );

        let bcast_key = WaMessageKey {
            remote_jid: Some("12345@broadcast".to_string()),
            participant: Some("573001111111@s.whatsapp.net".to_string()),
            from_me: Some(false),
            ..Default::default()
        };
        assert_eq!(get_chat_id(&bcast_key).unwrap(), "573001111111@s.whatsapp.net");
    }

    #[test]
    fn test_decrypt_poll_vote_and_event_response() {
        let enc_key = [11u8; 32];
        let iv = [22u8; 12];
        let poll_msg_id = "POLL_1";
        let creator = "573001111111@s.whatsapp.net";
        let voter = "573002222222@s.whatsapp.net";

        let mut sign = Vec::new();
        sign.extend_from_slice(poll_msg_id.as_bytes());
        sign.extend_from_slice(creator.as_bytes());
        sign.extend_from_slice(voter.as_bytes());
        sign.extend_from_slice(b"Poll Vote");
        sign.push(1);
        let key0 = hmac_sign(&enc_key, &[0u8; 32], HmacVariant::Sha256).unwrap();
        let dec_key = hmac_sign(&sign, &key0, HmacVariant::Sha256).unwrap();
        let aad = format!("{}\0{}", poll_msg_id, voter);

        let vote = PollVoteMessage {
            selected_options: vec![vec![1, 2, 3, 4]],
        };
        let ct = aes_encrypt_gcm(&vote.encode_to_vec(), &dec_key, &iv, aad.as_bytes()).unwrap();

        let decoded = decrypt_poll_vote(
            &ct,
            &iv,
            &PollDecryptContext {
                poll_creator_jid: creator,
                poll_msg_id,
                poll_enc_key: &enc_key,
                voter_jid: voter,
            },
        )
        .unwrap();
        assert_eq!(decoded.selected_options, vec![vec![1, 2, 3, 4]]);
    }

    #[tokio::test]
    async fn test_process_message_spoofed_self_only_dropped_and_revoke_emitted() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_procmsg_{}", suffix));
        let auth = Arc::new(use_multi_file_auth_state(&dir).await.unwrap());
        let repo = LibSignalRepository::new(Arc::clone(&auth), None);

        let mut creds = init_auth_creds().unwrap();
        creds.me = Some(ContactInfo {
            id: "573001111111:1@s.whatsapp.net".to_string(),
            name: Some("Luis".to_string()),
            lid: None,
        });

        let spoofed = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573009999999@s.whatsapp.net".to_string()),
                from_me: Some(false),
                id: Some("SPOOF_1".to_string()),
                ..Default::default()
            },
            message: Some(Message {
                protocol_message: Some(
                    ProtocolMessage {
                        r#type: Some(protocol_message::Type::AppStateSyncKeyShare as i32),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        let spoof_events = process_message(
            &spoofed,
            true,
            None,
            &creds,
            &repo,
            &auth,
            &MediaDownloadOptions::default(),
            |_| async { None },
        )
        .await
        .unwrap();
        assert!(spoof_events.is_empty());

        let revoke = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573009999999@s.whatsapp.net".to_string()),
                from_me: Some(false),
                id: Some("REV_OUTER".to_string()),
                ..Default::default()
            },
            message: Some(Message {
                protocol_message: Some(
                    ProtocolMessage {
                        r#type: Some(protocol_message::Type::Revoke as i32),
                        key: Some(MessageKey {
                            remote_jid: Some("573009999999@s.whatsapp.net".to_string()),
                            from_me: Some(false),
                            id: Some("ORIG_ID".to_string()),
                            participant: None,
                        }),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        let rev_events = process_message(
            &revoke,
            false,
            None,
            &creds,
            &repo,
            &auth,
            &MediaDownloadOptions::default(),
            |_| async { None },
        )
        .await
        .unwrap();
        assert_eq!(rev_events.len(), 1);
        match &rev_events[0] {
            ProcessMessageEvent::MessageRevoke { key, .. } => {
                assert_eq!(key.id.as_deref(), Some("ORIG_ID"));
            }
            other => panic!("unexpected event: {:?}", other),
        }

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
