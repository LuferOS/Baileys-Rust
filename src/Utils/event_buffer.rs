use crate::proto::{web_message_info, Message, PastParticipants, Reaction, UserReceipt};
use crate::types::{WaMessage, WaMessageKey};
use crate::utils::messages::{update_message_with_reaction, update_message_with_receipt};
use crate::utils::process_message::{
    is_real_message, should_increment_chat_unread, GroupMetadataPatch,
};
use prost::Message as ProstMessage;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

const MAX_HISTORY_CACHE_SIZE: usize = 10_000;
const BUFFER_TIMEOUT_MS: u64 = 30_000;
const FLUSH_DEBOUNCE_MS: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageUpsertType {
    Notify,
    Append,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BufferedChat {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub conversation_timestamp: Option<u64>,
    pub last_message_recv_timestamp: Option<u64>,
    pub unread_count: Option<Option<i32>>,
    pub archived: Option<bool>,
    pub pinned: Option<Option<i64>>,
    pub mute_end_time: Option<Option<i64>>,
    pub read_only: Option<bool>,
    pub end_of_history_transfer_type: Option<i32>,
    pub ephemeral_expiration: Option<Option<u32>>,
    pub ephemeral_setting_timestamp: Option<u64>,
    pub messages: Vec<WaMessage>,
}

pub type ChatUpdateCondition = Arc<dyn Fn(&BufferedEventData) -> Option<bool> + Send + Sync>;

#[derive(Clone, Default)]
pub struct BufferedChatUpdate {
    pub chat: BufferedChat,
    pub conditional: Option<ChatUpdateCondition>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferedContact {
    pub id: String,
    pub name: Option<String>,
    pub notify: Option<String>,
    pub verified_name: Option<String>,
    pub img_url: Option<String>,
    pub lid: Option<String>,
    pub phone_number: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BufferedMessageUpdate {
    pub key: WaMessageKey,
    pub status: Option<i32>,
    pub message: Option<Option<Message>>,
    pub message_timestamp: Option<u64>,
    pub message_stub_type: Option<i32>,
    pub message_stub_parameters: Option<Vec<String>>,
    pub starred: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct BufferedMessageUpsert {
    pub message: WaMessage,
    pub upsert_type: MessageUpsertType,
}

#[derive(Debug, Clone)]
pub struct BufferedMessageReactions {
    pub key: WaMessageKey,
    pub reactions: Vec<Reaction>,
}

#[derive(Debug, Clone)]
pub struct BufferedMessageReceipts {
    pub key: WaMessageKey,
    pub user_receipt: Vec<UserReceipt>,
}

#[derive(Debug, Clone, Default)]
pub struct HistorySetsBuffer {
    pub chats: HashMap<String, BufferedChat>,
    pub messages: HashMap<String, WaMessage>,
    pub contacts: HashMap<String, BufferedContact>,
    pub past_participants: Vec<PastParticipants>,
    pub sync_type: Option<i32>,
    pub progress: Option<u32>,
    pub chunk_order: Option<u32>,
    pub peer_data_request_session_id: Option<String>,
    pub is_latest: bool,
    pub empty: bool,
}

#[derive(Clone, Default)]
pub struct BufferedEventData {
    pub history_sets: HistorySetsBuffer,
    pub chat_upserts: HashMap<String, BufferedChat>,
    pub chat_updates: HashMap<String, BufferedChatUpdate>,
    pub chat_deletes: HashSet<String>,
    pub contact_upserts: HashMap<String, BufferedContact>,
    pub contact_updates: HashMap<String, BufferedContact>,
    pub message_upserts: HashMap<String, BufferedMessageUpsert>,
    pub message_updates: HashMap<String, BufferedMessageUpdate>,
    pub message_reactions: HashMap<String, BufferedMessageReactions>,
    pub message_deletes: HashMap<String, WaMessageKey>,
    pub message_receipts: HashMap<String, BufferedMessageReceipts>,
    pub group_updates: HashMap<String, GroupMetadataPatch>,
}

impl BufferedEventData {
    pub fn new() -> Self {
        Self {
            history_sets: HistorySetsBuffer {
                empty: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct HistorySetPayload {
    pub chats: Vec<BufferedChat>,
    pub messages: Vec<WaMessage>,
    pub contacts: Vec<BufferedContact>,
    pub past_participants: Vec<PastParticipants>,
    pub sync_type: Option<i32>,
    pub progress: Option<u32>,
    pub is_latest: bool,
    pub chunk_order: Option<u32>,
    pub peer_data_request_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MessagesUpsertPayload {
    pub messages: Vec<WaMessage>,
    pub upsert_type: MessageUpsertType,
}

#[derive(Clone)]
pub enum BufferableEvent {
    MessagingHistorySet(HistorySetPayload),
    ChatsUpsert(Vec<BufferedChat>),
    ChatsUpdate(Vec<BufferedChatUpdate>),
    ChatsDelete(Vec<String>),
    ContactsUpsert(Vec<BufferedContact>),
    ContactsUpdate(Vec<BufferedContact>),
    MessagesUpsert(MessagesUpsertPayload),
    MessagesUpdate(Vec<BufferedMessageUpdate>),
    MessagesDelete(Vec<WaMessageKey>),
    MessagesReaction(Vec<(WaMessageKey, Reaction)>),
    MessageReceiptUpdate(Vec<(WaMessageKey, UserReceipt)>),
    GroupsUpdate(Vec<GroupMetadataPatch>),
}

#[derive(Debug, Clone, Default)]
pub struct BaileysEventBatch {
    pub messaging_history_set: Option<HistorySetPayload>,
    pub chats_upsert: Vec<BufferedChat>,
    pub chats_update: Vec<BufferedChat>,
    pub chats_delete: Vec<String>,
    pub contacts_upsert: Vec<BufferedContact>,
    pub contacts_update: Vec<BufferedContact>,
    pub messages_upsert: Option<MessagesUpsertPayload>,
    pub messages_update: Vec<BufferedMessageUpdate>,
    pub messages_delete: Vec<WaMessageKey>,
    pub messages_reaction: Vec<(WaMessageKey, Reaction)>,
    pub message_receipt_update: Vec<(WaMessageKey, UserReceipt)>,
    pub groups_update: Vec<GroupMetadataPatch>,
}

impl BaileysEventBatch {
    pub fn is_empty(&self) -> bool {
        self.messaging_history_set.is_none()
            && self.chats_upsert.is_empty()
            && self.chats_update.is_empty()
            && self.chats_delete.is_empty()
            && self.contacts_upsert.is_empty()
            && self.contacts_update.is_empty()
            && self.messages_upsert.is_none()
            && self.messages_update.is_empty()
            && self.messages_delete.is_empty()
            && self.messages_reaction.is_empty()
            && self.message_receipt_update.is_empty()
            && self.groups_update.is_empty()
    }
}

pub fn stringify_message_key(key: &WaMessageKey) -> String {
    format!(
        "{},{},{}",
        key.remote_jid.as_deref().unwrap_or(""),
        key.id.as_deref().unwrap_or(""),
        if key.from_me == Some(true) { "1" } else { "0" }
    )
}

pub fn concat_chats(a: &mut BufferedChat, b: BufferedChat) {
    if !b.id.is_empty() {
        a.id = b.id;
    }
    if b.name.is_some() {
        a.name = b.name;
    }
    if b.description.is_some() {
        a.description = b.description;
    }
    if b.conversation_timestamp.is_some() {
        a.conversation_timestamp = b.conversation_timestamp;
    }
    if b.last_message_recv_timestamp.is_some() {
        a.last_message_recv_timestamp = b.last_message_recv_timestamp;
    }

    match (a.unread_count, b.unread_count) {
        (Some(Some(av)), Some(None)) if av < 0 => {
            a.unread_count = None;
        }
        (Some(Some(av)), Some(Some(bv))) => {
            if bv >= 0 {
                a.unread_count = Some(Some(bv.max(0) + av.max(0)));
            } else {
                a.unread_count = Some(Some(bv));
            }
        }
        (_, Some(b_val)) => {
            a.unread_count = Some(b_val);
        }
        (_, None) => {}
    }

    if b.archived.is_some() {
        a.archived = b.archived;
    }
    if b.pinned.is_some() {
        a.pinned = b.pinned;
    }
    if b.mute_end_time.is_some() {
        a.mute_end_time = b.mute_end_time;
    }
    if b.read_only.is_some() {
        a.read_only = b.read_only;
    }
    if b.end_of_history_transfer_type.is_some() {
        a.end_of_history_transfer_type = b.end_of_history_transfer_type;
    }
    if b.ephemeral_expiration.is_some() {
        a.ephemeral_expiration = b.ephemeral_expiration;
    }
    if b.ephemeral_setting_timestamp.is_some() {
        a.ephemeral_setting_timestamp = b.ephemeral_setting_timestamp;
    }
    if !b.messages.is_empty() {
        a.messages = b.messages;
    }
}

fn merge_contact(target: &mut BufferedContact, src: BufferedContact) {
    if !src.id.is_empty() {
        target.id = src.id;
    }
    if src.name.is_some() {
        target.name = src.name;
    }
    if src.notify.is_some() {
        target.notify = src.notify;
    }
    if src.verified_name.is_some() {
        target.verified_name = src.verified_name;
    }
    if src.img_url.is_some() {
        target.img_url = src.img_url;
    }
    if src.lid.is_some() {
        target.lid = src.lid;
    }
    if src.phone_number.is_some() {
        target.phone_number = src.phone_number;
    }
    if src.username.is_some() {
        target.username = src.username;
    }
}

fn apply_message_update(msg: &mut WaMessage, upd: &BufferedMessageUpdate) {
    if let Some(status) = upd.status {
        msg.status = Some(status);
    }
    if let Some(ref m) = upd.message {
        msg.message = m.clone();
    }
    if let Some(ts) = upd.message_timestamp {
        msg.message_timestamp = Some(ts);
    }
    if let Some(stub) = upd.message_stub_type {
        msg.message_stub_type = Some(stub);
    }
    if let Some(ref params) = upd.message_stub_parameters {
        msg.message_stub_parameters = params.clone();
    }
}

fn merge_message_update(target: &mut BufferedMessageUpdate, src: BufferedMessageUpdate) {
    if src.status.is_some() {
        target.status = src.status;
    }
    if src.message.is_some() {
        target.message = src.message;
    }
    if src.message_timestamp.is_some() {
        target.message_timestamp = src.message_timestamp;
    }
    if src.message_stub_type.is_some() {
        target.message_stub_type = src.message_stub_type;
    }
    if src.message_stub_parameters.is_some() {
        target.message_stub_parameters = src.message_stub_parameters;
    }
    if src.starred.is_some() {
        target.starred = src.starred;
    }
}

fn absorb_chat_update(data: &mut BufferedEventData, chat_id: &str, in_history: bool) {
    let Some(mut update) = data.chat_updates.remove(chat_id) else {
        return;
    };

    let cond = update
        .conditional
        .as_ref()
        .map(|f| f(data))
        .unwrap_or(Some(true));

    match cond {
        Some(true) => {
            update.conditional = None;
            let target_opt = if in_history {
                data.history_sets.chats.get_mut(chat_id)
            } else {
                data.chat_upserts.get_mut(chat_id)
            };
            if let Some(existing) = target_opt {
                let mut merged = update.chat;
                concat_chats(&mut merged, existing.clone());
                *existing = merged;
            }
        }
        None => {
            data.chat_updates.insert(chat_id.to_string(), update);
        }
        Some(false) => {}
    }
}

fn decrement_chat_read_counter(data: &mut BufferedEventData, message: &WaMessage) {
    let Some(chat_id) = message.key.remote_jid.as_deref() else {
        return;
    };
    if !is_real_message(message) || !should_increment_chat_unread(message) {
        return;
    }

    let chat_opt = if let Some(upd) = data.chat_updates.get_mut(chat_id) {
        Some(&mut upd.chat)
    } else {
        data.chat_upserts.get_mut(chat_id)
    };

    if let Some(chat) = chat_opt {
        if let Some(Some(count)) = chat.unread_count {
            if count > 0 {
                let next = count - 1;
                chat.unread_count = if next == 0 { None } else { Some(Some(next)) };
            }
        }
    }
}

fn merge_past_participants(existing: &mut Vec<PastParticipants>, incoming: Vec<PastParticipants>) {
    if incoming.is_empty() {
        return;
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_key: HashMap<String, (PastParticipants, HashSet<Vec<u8>>)> = HashMap::new();

    let mut ingest = |entry: PastParticipants| {
        let key = format!("{:?}", entry.group_jid);
        if let Some((slot, seen)) = by_key.get_mut(&key) {
            for p in entry.past_participants {
                let sig = p.encode_to_vec();
                if seen.insert(sig) {
                    slot.past_participants.push(p);
                }
            }
        } else {
            let mut seen = HashSet::new();
            let mut deduped = Vec::new();
            for p in entry.past_participants {
                let sig = p.encode_to_vec();
                if seen.insert(sig) {
                    deduped.push(p);
                }
            }
            order.push(key.clone());
            by_key.insert(
                key,
                (
                    PastParticipants {
                        group_jid: entry.group_jid,
                        past_participants: deduped,
                    },
                    seen,
                ),
            );
        }
    };

    for entry in std::mem::take(existing) {
        ingest(entry);
    }
    for entry in incoming {
        ingest(entry);
    }

    for key in order {
        if let Some((entry, _)) = by_key.remove(&key) {
            existing.push(entry);
        }
    }
}

fn append_event(
    data: &mut BufferedEventData,
    history_cache: &mut HashSet<String>,
    event: BufferableEvent,
) {
    match event {
        BufferableEvent::MessagingHistorySet(payload) => {
            for chat in payload.chats {
                let id = chat.id.clone();
                if let Some(existing) = data.history_sets.chats.get_mut(&id) {
                    existing.end_of_history_transfer_type = chat.end_of_history_transfer_type;
                } else if !history_cache.contains(&id) {
                    data.history_sets.chats.insert(id.clone(), chat);
                    history_cache.insert(id.clone());
                    absorb_chat_update(data, &id, true);
                }
            }

            for contact in payload.contacts {
                let id = contact.id.clone();
                if let Some(existing) = data.history_sets.contacts.get_mut(&id) {
                    merge_contact(existing, contact);
                } else {
                    let cache_id = format!("c:{}", id);
                    let has_any_name = contact.notify.is_some()
                        || contact.name.is_some()
                        || contact.verified_name.is_some();
                    if !history_cache.contains(&cache_id) || has_any_name {
                        data.history_sets.contacts.insert(id, contact);
                        history_cache.insert(cache_id);
                    }
                }
            }

            for msg in payload.messages {
                let key = stringify_message_key(&msg.key);
                if !data.history_sets.messages.contains_key(&key) && !history_cache.contains(&key) {
                    data.history_sets.messages.insert(key.clone(), msg);
                    history_cache.insert(key);
                }
            }

            data.history_sets.empty = false;
            data.history_sets.sync_type = payload.sync_type;
            merge_past_participants(
                &mut data.history_sets.past_participants,
                payload.past_participants,
            );
            data.history_sets.progress = payload.progress;
            data.history_sets.chunk_order = payload.chunk_order;
            data.history_sets.peer_data_request_session_id = payload.peer_data_request_session_id;
            data.history_sets.is_latest = payload.is_latest || data.history_sets.is_latest;
        }
        BufferableEvent::ChatsUpsert(chats) => {
            for chat in chats {
                let id = chat.id.clone();
                let in_history = if let Some(existing) = data.chat_upserts.get_mut(&id) {
                    concat_chats(existing, chat);
                    false
                } else if let Some(hist_chat) = data.history_sets.chats.get_mut(&id) {
                    concat_chats(hist_chat, chat);
                    true
                } else {
                    data.chat_upserts.insert(id.clone(), chat);
                    false
                };

                absorb_chat_update(data, &id, in_history);
                data.chat_deletes.remove(&id);
            }
        }
        BufferableEvent::ChatsUpdate(updates) => {
            for mut update in updates {
                let chat_id = update.chat.id.clone();
                let cond = update
                    .conditional
                    .as_ref()
                    .map(|f| f(data))
                    .unwrap_or(Some(true));

                match cond {
                    Some(true) => {
                        update.conditional = None;
                        if let Some(hist) = data.history_sets.chats.get_mut(&chat_id) {
                            concat_chats(hist, update.chat);
                        } else if let Some(upsert) = data.chat_upserts.get_mut(&chat_id) {
                            concat_chats(upsert, update.chat);
                        } else {
                            let entry = data
                                .chat_updates
                                .entry(chat_id.clone())
                                .or_insert_with(|| BufferedChatUpdate {
                                    chat: BufferedChat {
                                        id: chat_id.clone(),
                                        ..Default::default()
                                    },
                                    conditional: None,
                                });
                            concat_chats(&mut entry.chat, update.chat);
                        }
                    }
                    None => {
                        data.chat_updates.insert(chat_id.clone(), update);
                    }
                    Some(false) => {}
                }

                data.chat_deletes.remove(&chat_id);
            }
        }
        BufferableEvent::ChatsDelete(chat_ids) => {
            for chat_id in chat_ids {
                data.chat_deletes.insert(chat_id.clone());
                data.chat_updates.remove(&chat_id);
                data.chat_upserts.remove(&chat_id);
                data.history_sets.chats.remove(&chat_id);
            }
        }
        BufferableEvent::ContactsUpsert(contacts) => {
            for contact in contacts {
                let id = contact.id.clone();
                if let Some(existing) = data.contact_upserts.get_mut(&id) {
                    merge_contact(existing, contact.clone());
                } else if let Some(hist) = data.history_sets.contacts.get_mut(&id) {
                    merge_contact(hist, contact.clone());
                } else {
                    data.contact_upserts.insert(id.clone(), contact.clone());
                }

                if let Some(mut prior_update) = data.contact_updates.remove(&id) {
                    merge_contact(&mut prior_update, contact);
                    if let Some(existing) = data.contact_upserts.get_mut(&id) {
                        *existing = prior_update;
                    } else if let Some(hist) = data.history_sets.contacts.get_mut(&id) {
                        *hist = prior_update;
                    }
                }
            }
        }
        BufferableEvent::ContactsUpdate(updates) => {
            for update in updates {
                let id = update.id.clone();
                if let Some(hist) = data.history_sets.contacts.get_mut(&id) {
                    merge_contact(hist, update);
                } else if let Some(upsert) = data.contact_upserts.get_mut(&id) {
                    merge_contact(upsert, update);
                } else {
                    let entry = data
                        .contact_updates
                        .entry(id.clone())
                        .or_insert_with(|| BufferedContact {
                            id,
                            ..Default::default()
                        });
                    merge_contact(entry, update);
                }
            }
        }
        BufferableEvent::MessagesUpsert(payload) => {
            for mut message in payload.messages {
                let key = stringify_message_key(&message.key);

                if let Some(existing_ts) = data
                    .message_upserts
                    .get(&key)
                    .map(|u| u.message.message_timestamp)
                    .or_else(|| {
                        data.history_sets
                            .messages
                            .get(&key)
                            .map(|m| m.message_timestamp)
                    })
                {
                    message.message_timestamp = existing_ts;
                }

                if let Some(prior_upd) = data.message_updates.remove(&key) {
                    apply_message_update(&mut message, &prior_upd);
                }

                if data.history_sets.messages.contains_key(&key) {
                    data.history_sets.messages.insert(key, message);
                } else {
                    let prev_notify = data
                        .message_upserts
                        .get(&key)
                        .is_some_and(|u| u.upsert_type == MessageUpsertType::Notify);
                    let final_type =
                        if payload.upsert_type == MessageUpsertType::Notify || prev_notify {
                            MessageUpsertType::Notify
                        } else {
                            payload.upsert_type
                        };
                    data.message_upserts.insert(
                        key,
                        BufferedMessageUpsert {
                            message,
                            upsert_type: final_type,
                        },
                    );
                }
            }
        }
        BufferableEvent::MessagesUpdate(updates) => {
            for upd in updates {
                let key_str = stringify_message_key(&upd.key);
                let is_read_not_me = upd.status == Some(web_message_info::Status::Read as i32)
                    && upd.key.from_me != Some(true);

                let existing_msg_clone =
                    if let Some(msg) = data.history_sets.messages.get_mut(&key_str) {
                        apply_message_update(msg, &upd);
                        Some(msg.clone())
                    } else if let Some(slot) = data.message_upserts.get_mut(&key_str) {
                        apply_message_update(&mut slot.message, &upd);
                        Some(slot.message.clone())
                    } else {
                        None
                    };

                if let Some(existing) = existing_msg_clone {
                    if is_read_not_me {
                        decrement_chat_read_counter(data, &existing);
                    }
                } else {
                    let entry = data
                        .message_updates
                        .entry(key_str)
                        .or_insert_with(|| BufferedMessageUpdate {
                            key: upd.key.clone(),
                            ..Default::default()
                        });
                    merge_message_update(entry, upd);
                }
            }
        }
        BufferableEvent::MessagesDelete(keys) => {
            for key in keys {
                let key_str = stringify_message_key(&key);
                data.message_deletes.entry(key_str.clone()).or_insert(key);
                data.message_upserts.remove(&key_str);
                data.message_updates.remove(&key_str);
            }
        }
        BufferableEvent::MessagesReaction(reactions) => {
            for (key, reaction) in reactions {
                let key_str = stringify_message_key(&key);
                if let Some(existing) = data.message_upserts.get_mut(&key_str) {
                    update_message_with_reaction(&mut existing.message, reaction);
                } else {
                    let entry = data
                        .message_reactions
                        .entry(key_str)
                        .or_insert_with(|| BufferedMessageReactions {
                            key: key.clone(),
                            reactions: Vec::new(),
                        });
                    let mut temp = WaMessage {
                        reactions: std::mem::take(&mut entry.reactions),
                        ..Default::default()
                    };
                    update_message_with_reaction(&mut temp, reaction);
                    entry.reactions = temp.reactions;
                }
            }
        }
        BufferableEvent::MessageReceiptUpdate(receipts) => {
            for (key, receipt) in receipts {
                let key_str = stringify_message_key(&key);
                if let Some(existing) = data.message_upserts.get_mut(&key_str) {
                    update_message_with_receipt(&mut existing.message, receipt);
                } else {
                    let entry = data
                        .message_receipts
                        .entry(key_str)
                        .or_insert_with(|| BufferedMessageReceipts {
                            key: key.clone(),
                            user_receipt: Vec::new(),
                        });
                    let mut temp = WaMessage {
                        user_receipt: std::mem::take(&mut entry.user_receipt),
                        ..Default::default()
                    };
                    update_message_with_receipt(&mut temp, receipt);
                    entry.user_receipt = temp.user_receipt;
                }
            }
        }
        BufferableEvent::GroupsUpdate(updates) => {
            for update in updates {
                data.group_updates
                    .entry(update.id.clone())
                    .or_insert(update);
            }
        }
    }
}

fn consolidate_events(data: BufferedEventData) -> BaileysEventBatch {
    let mut batch = BaileysEventBatch::default();

    if !data.history_sets.empty {
        batch.messaging_history_set = Some(HistorySetPayload {
            chats: data.history_sets.chats.into_values().collect(),
            messages: data.history_sets.messages.into_values().collect(),
            contacts: data.history_sets.contacts.into_values().collect(),
            past_participants: data.history_sets.past_participants,
            sync_type: data.history_sets.sync_type,
            progress: data.history_sets.progress,
            is_latest: data.history_sets.is_latest,
            chunk_order: data.history_sets.chunk_order,
            peer_data_request_session_id: data.history_sets.peer_data_request_session_id,
        });
    }

    batch.chats_upsert = data.chat_upserts.into_values().collect();
    batch.chats_update = data
        .chat_updates
        .into_values()
        .map(|u| u.chat)
        .collect();
    batch.chats_delete = data.chat_deletes.into_iter().collect();

    if !data.message_upserts.is_empty() {
        let mut upserts: Vec<BufferedMessageUpsert> = data.message_upserts.into_values().collect();
        let upsert_type = upserts[0].upsert_type;
        let messages = upserts.drain(..).map(|u| u.message).collect();
        batch.messages_upsert = Some(MessagesUpsertPayload {
            messages,
            upsert_type,
        });
    }

    batch.messages_update = data.message_updates.into_values().collect();
    batch.messages_delete = data.message_deletes.into_values().collect();

    for entry in data.message_reactions.into_values() {
        for reaction in entry.reactions {
            batch
                .messages_reaction
                .push((entry.key.clone(), reaction));
        }
    }

    for entry in data.message_receipts.into_values() {
        for receipt in entry.user_receipt {
            batch
                .message_receipt_update
                .push((entry.key.clone(), receipt));
        }
    }

    batch.contacts_upsert = data.contact_upserts.into_values().collect();
    batch.contacts_update = data.contact_updates.into_values().collect();
    batch.groups_update = data.group_updates.into_values().collect();

    batch
}

struct EventBufferInner {
    history_cache: HashSet<String>,
    data: BufferedEventData,
    is_buffering: bool,
    buffer_count: usize,
    buffer_timeout: Option<JoinHandle<()>>,
    flush_pending_timeout: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct EventBuffer {
    inner: Arc<StdMutex<EventBufferInner>>,
    tx: broadcast::Sender<BaileysEventBatch>,
}

impl Default for EventBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBuffer {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(StdMutex::new(EventBufferInner {
                history_cache: HashSet::new(),
                data: BufferedEventData::new(),
                is_buffering: false,
                buffer_count: 0,
                buffer_timeout: None,
                flush_pending_timeout: None,
            })),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BaileysEventBatch> {
        self.tx.subscribe()
    }

    pub fn is_buffering(&self) -> bool {
        self.inner.lock().unwrap().is_buffering
    }

    pub fn buffer(&self) {
        let mut st = self.inner.lock().unwrap();
        if !st.is_buffering {
            st.is_buffering = true;
            st.buffer_count = 0;

            if let Some(handle) = st.buffer_timeout.take() {
                handle.abort();
            }

            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let this = self.clone();
                st.buffer_timeout = Some(rt.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(BUFFER_TIMEOUT_MS)).await;
                    if this.is_buffering() {
                        this.flush();
                    }
                }));
            }
        }
        st.buffer_count += 1;
    }

    pub fn flush(&self) -> bool {
        let consolidated = {
            let mut st = self.inner.lock().unwrap();
            if !st.is_buffering {
                return false;
            }
            st.is_buffering = false;
            st.buffer_count = 0;

            if let Some(handle) = st.buffer_timeout.take() {
                handle.abort();
            }
            if let Some(handle) = st.flush_pending_timeout.take() {
                handle.abort();
            }
            if st.history_cache.len() > MAX_HISTORY_CACHE_SIZE {
                st.history_cache.clear();
            }

            let mut old_data = std::mem::replace(&mut st.data, BufferedEventData::new());
            let mut deferred_updates = HashMap::new();
            let conditional_ids: Vec<String> = old_data
                .chat_updates
                .iter()
                .filter_map(|(k, v)| {
                    if v.conditional.is_some() {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for id in conditional_ids {
                if let Some(upd) = old_data.chat_updates.remove(&id) {
                    deferred_updates.insert(id, upd);
                }
            }
            st.data.chat_updates = deferred_updates;

            consolidate_events(old_data)
        };

        if !consolidated.is_empty() {
            let _ = self.tx.send(consolidated);
        }
        true
    }

    pub fn emit(&self, event: BufferableEvent) -> bool {
        let immediate_batch: Option<BaileysEventBatch> = {
            let mut st = self.inner.lock().unwrap();

            if let BufferableEvent::MessagesUpsert(ref payload) = event {
                let mismatch = st
                    .data
                    .message_upserts
                    .values()
                    .next()
                    .is_some_and(|first| first.upsert_type != payload.upsert_type);
                if mismatch {
                    let drained: Vec<BufferedMessageUpsert> =
                        st.data.message_upserts.drain().map(|(_, v)| v).collect();
                    let buffered_type = drained[0].upsert_type;
                    let batch = BaileysEventBatch {
                        messages_upsert: Some(MessagesUpsertPayload {
                            messages: drained.into_iter().map(|u| u.message).collect(),
                            upsert_type: buffered_type,
                        }),
                        ..Default::default()
                    };
                    let _ = self.tx.send(batch);
                }
            }

            if st.is_buffering {
                let inner = &mut *st;
                append_event(&mut inner.data, &mut inner.history_cache, event);
                None
            } else {
                let mut temp = BufferedEventData::new();
                let mut temp_cache = HashSet::new();
                append_event(&mut temp, &mut temp_cache, event);
                Some(consolidate_events(temp))
            }
        };

        if let Some(batch) = immediate_batch {
            if !batch.is_empty() {
                let _ = self.tx.send(batch);
            }
        }
        true
    }

    pub async fn run_buffered<F, Fut, T>(&self, work: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        self.buffer();
        let result = work().await;

        let mut st = self.inner.lock().unwrap();
        st.buffer_count = st.buffer_count.saturating_sub(1);
        if st.buffer_count == 0 && st.flush_pending_timeout.is_none() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let this = self.clone();
                st.flush_pending_timeout = Some(rt.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(FLUSH_DEBOUNCE_MS)).await;
                    this.flush();
                }));
            }
        }

        result
    }

    pub fn destroy(&self) {
        let mut st = self.inner.lock().unwrap();
        if let Some(handle) = st.buffer_timeout.take() {
            handle.abort();
        }
        if let Some(handle) = st.flush_pending_timeout.take() {
            handle.abort();
        }
        st.history_cache.clear();
        st.data = BufferedEventData::new();
        st.is_buffering = false;
        st.buffer_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_buffer_consolidation_and_conditional_chat_update() {
        let ev = EventBuffer::new();
        let mut rx = ev.subscribe();

        ev.buffer();
        assert!(ev.is_buffering());

        ev.emit(BufferableEvent::ChatsUpdate(vec![BufferedChatUpdate {
            chat: BufferedChat {
                id: "573001@s.whatsapp.net".to_string(),
                archived: Some(true),
                ..Default::default()
            },
            conditional: Some(Arc::new(|data| {
                if data.chat_upserts.contains_key("573001@s.whatsapp.net") {
                    Some(true)
                } else {
                    None
                }
            })),
        }]));

        ev.emit(BufferableEvent::ChatsUpsert(vec![BufferedChat {
            id: "573001@s.whatsapp.net".to_string(),
            name: Some("Contacto 1".to_string()),
            unread_count: Some(Some(2)),
            ..Default::default()
        }]));

        ev.emit(BufferableEvent::ChatsUpdate(vec![BufferedChatUpdate {
            chat: BufferedChat {
                id: "573001@s.whatsapp.net".to_string(),
                unread_count: Some(Some(3)),
                ..Default::default()
            },
            conditional: None,
        }]));

        assert!(ev.flush());
        assert!(!ev.is_buffering());

        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.chats_upsert.len(), 1);
        assert_eq!(batch.chats_upsert[0].archived, Some(true));
        assert_eq!(batch.chats_upsert[0].name.as_deref(), Some("Contacto 1"));
        assert_eq!(batch.chats_upsert[0].unread_count, Some(Some(5)));
    }

    #[test]
    fn test_message_upsert_type_mismatch_and_delete_cleanup() {
        let ev = EventBuffer::new();
        let mut rx = ev.subscribe();

        ev.buffer();
        let msg_a = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573002@s.whatsapp.net".to_string()),
                id: Some("M_A".to_string()),
                from_me: Some(false),
                ..Default::default()
            },
            message: Some(Message {
                conversation: Some("hola".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg_b = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573002@s.whatsapp.net".to_string()),
                id: Some("M_B".to_string()),
                from_me: Some(false),
                ..Default::default()
            },
            message: Some(Message {
                conversation: Some("append".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        ev.emit(BufferableEvent::MessagesUpsert(MessagesUpsertPayload {
            messages: vec![msg_a],
            upsert_type: MessageUpsertType::Notify,
        }));
        ev.emit(BufferableEvent::MessagesUpsert(MessagesUpsertPayload {
            messages: vec![msg_b.clone()],
            upsert_type: MessageUpsertType::Append,
        }));

        let first = rx.try_recv().unwrap();
        assert_eq!(
            first.messages_upsert.as_ref().unwrap().upsert_type,
            MessageUpsertType::Notify
        );

        ev.emit(BufferableEvent::MessagesDelete(vec![msg_b.key]));
        ev.flush();

        let second = rx.try_recv().unwrap();
        assert!(second.messages_upsert.is_none());
        assert_eq!(second.messages_delete.len(), 1);
    }
}
