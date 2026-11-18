use crate::defaults::WA_DEFAULT_EPHEMERAL;
use crate::proto::message::{
    poll_creation_message, protocol_message, AudioMessage, ContactMessage, ContactsArrayMessage,
    DocumentMessage, ExtendedTextMessage, FutureProofMessage, GroupInviteMessage, ImageMessage,
    LocationMessage, PinInChatMessage, PollCreationMessage, ProtocolMessage, ReactionMessage,
    RequestPhoneNumberMessage, StickerMessage, VideoMessage,
};
use crate::proto::{
    web_message_info, ContextInfo, Message, MessageContextInfo, PollUpdate, Reaction, UserReceipt,
};
use crate::types::{WaMessage, WaMessageKey};
use crate::utils::crypto::sha256;
use crate::utils::generics::{
    generate_message_id_v2, get_proto_key_author, now_millis, unix_timestamp_seconds,
};
use crate::wa_binary::{
    is_jid_group, is_jid_newsletter, is_jid_status_broadcast, jid_normalized_user,
};
use rand::{rngs::OsRng, RngCore};
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageGenerationError {
    #[error("no content in message")]
    NoContent,
    #[error("require at least 1 contact")]
    EmptyContacts,
    #[error("invalid poll selectable_count: must be >= 0 and <= {0}")]
    InvalidPollSelectableCount(usize),
    #[error("given message is not a media message")]
    NotAMediaMessage,
}

#[derive(Debug, Clone)]
pub struct ContactInput {
    pub display_name: Option<String>,
    pub vcard: String,
}

#[derive(Debug, Clone)]
pub struct LocationInput {
    pub degrees_latitude: f64,
    pub degrees_longitude: f64,
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReactionInput {
    pub key: WaMessageKey,
    pub text: String,
    pub sender_timestamp_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct GroupInviteInput {
    pub jid: String,
    pub invite_code: String,
    pub invite_expiration: i64,
    pub subject: String,
    pub text: String,
    pub jpeg_thumbnail: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PinInput {
    pub key: WaMessageKey,
    pub pin_type: i32,
    pub time_secs: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PollInput {
    pub name: String,
    pub values: Vec<String>,
    pub selectable_count: u32,
    pub to_announcement_group: bool,
    pub message_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum AnyMessageContent {
    Text(String),
    Contacts {
        display_name: Option<String>,
        contacts: Vec<ContactInput>,
    },
    Location(LocationInput),
    React(ReactionInput),
    Delete(WaMessageKey),
    Forward {
        message: Box<WaMessage>,
        force: bool,
    },
    DisappearingMessagesInChat(Option<u32>),
    GroupInvite(GroupInviteInput),
    Pin(PinInput),
    Poll(PollInput),
    SharePhoneNumber,
    RequestPhoneNumber,
    Raw(Message),
}

#[derive(Debug, Clone, Default)]
pub struct MessageGenerationOptions {
    pub user_jid: Option<String>,
    pub message_id: Option<String>,
    pub timestamp: Option<u64>,
    pub quoted: Option<Box<WaMessage>>,
    pub ephemeral_expiration: Option<u32>,
    pub mentions: Vec<String>,
    pub view_once: bool,
    pub edit: Option<WaMessageKey>,
    pub context_info: Option<ContextInfo>,
    pub background_color: Option<String>,
    pub font: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteAggregation {
    pub name: String,
    pub voters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedMessageKeys {
    pub jid: String,
    pub participant: Option<String>,
    pub message_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum MediaContent {
    Image(ImageMessage),
    Video(VideoMessage),
    Audio(AudioMessage),
    Document(DocumentMessage),
    Sticker(StickerMessage),
}

pub fn extract_url_from_text(text: &str) -> Option<&str> {
    let start = text.find("https://")?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace())
        .unwrap_or(rest.len());
    let candidate = &rest[..end];
    let after_scheme = candidate.strip_prefix("https://")?;
    let host_part = after_scheme.split('/').next().unwrap_or("");
    if host_part.contains('@') || !host_part.contains('.') || host_part.len() < 4 {
        return None;
    }
    Some(candidate)
}

pub fn assert_color_hex(color: &str) -> Option<u32> {
    let mut hex = color.trim().trim_start_matches('#').to_string();
    if hex.len() <= 6 {
        hex = format!("FF{:0>6}", hex);
    }
    u32::from_str_radix(&hex, 16).ok()
}

pub fn prepare_disappearing_message_setting_content(ephemeral_expiration: Option<u32>) -> Message {
    let exp = ephemeral_expiration.unwrap_or(0);
    let inner = Message {
        protocol_message: Some(
            ProtocolMessage {
                r#type: Some(protocol_message::Type::EphemeralSetting as i32),
                ephemeral_expiration: Some(exp),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    };
    Message {
        ephemeral_message: Some(
            FutureProofMessage {
                message: Some(inner.into()),
            }
            .into(),
        ),
        ..Default::default()
    }
}

fn attach_context_info(msg: &mut Message, updater: impl FnOnce(&mut ContextInfo)) {
    if let Some(ref mut m) = msg.extended_text_message {
        let inner: &mut ExtendedTextMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.image_message {
        let inner: &mut ImageMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.video_message {
        let inner: &mut VideoMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.audio_message {
        let inner: &mut AudioMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.document_message {
        let inner: &mut DocumentMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.sticker_message {
        let inner: &mut StickerMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.contact_message {
        let inner: &mut ContactMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.contacts_array_message {
        let inner: &mut ContactsArrayMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.location_message {
        let inner: &mut LocationMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.group_invite_message {
        let inner: &mut GroupInviteMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.poll_creation_message {
        let inner: &mut PollCreationMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.poll_creation_message_v2 {
        let inner: &mut PollCreationMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.poll_creation_message_v3 {
        let inner: &mut PollCreationMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    } else if let Some(ref mut m) = msg.ptv_message {
        let inner: &mut VideoMessage = BorrowMut::borrow_mut(m);
        let ci = inner
            .context_info
            .get_or_insert_with(|| ContextInfo::default().into());
        updater(BorrowMut::borrow_mut(ci));
    }
}

fn read_forwarding_score(msg: &Message) -> u32 {
    let get_score = |ci: Option<&ContextInfo>| ci.and_then(|c| c.forwarding_score).unwrap_or(0);
    if let Some(ref m) = msg.extended_text_message {
        let inner: &ExtendedTextMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    if let Some(ref m) = msg.image_message {
        let inner: &ImageMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    if let Some(ref m) = msg.video_message {
        let inner: &VideoMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    if let Some(ref m) = msg.audio_message {
        let inner: &AudioMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    if let Some(ref m) = msg.document_message {
        let inner: &DocumentMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    if let Some(ref m) = msg.sticker_message {
        let inner: &StickerMessage = Borrow::borrow(m);
        return get_score(inner.context_info.as_ref().map(|c| Borrow::borrow(c)));
    }
    0
}

pub fn generate_forward_message_content(
    message: &WaMessage,
    force_forward: bool,
) -> Result<Message, MessageGenerationError> {
    let Some(raw) = &message.message else {
        return Err(MessageGenerationError::NoContent);
    };

    let mut content = normalize_message_content(raw);
    let mut score = read_forwarding_score(&content);
    if !(message.key.from_me == Some(true) && !force_forward) {
        score = score.saturating_add(1);
    }

    if let Some(text) = content.conversation.take() {
        content.extended_text_message = Some(
            ExtendedTextMessage {
                text: Some(text),
                ..Default::default()
            }
            .into(),
        );
    }

    attach_context_info(&mut content, |ci| {
        if score > 0 {
            *ci = ContextInfo {
                forwarding_score: Some(score),
                is_forwarded: Some(true),
                ..Default::default()
            };
        } else {
            *ci = ContextInfo::default();
        }
    });

    Ok(content)
}

pub fn generate_wa_message_content(
    content: AnyMessageContent,
    options: &MessageGenerationOptions,
) -> Result<Message, MessageGenerationError> {
    let mut m = Message::default();

    match content {
        AnyMessageContent::Text(text) => {
            let mut ext = ExtendedTextMessage {
                text: Some(text),
                ..Default::default()
            };
            if let Some(ref bg) = options.background_color {
                ext.background_argb = assert_color_hex(bg);
            }
            if let Some(font) = options.font {
                ext.font = Some(font);
            }
            m.extended_text_message = Some(ext.into());
        }
        AnyMessageContent::Contacts {
            display_name,
            contacts,
        } => {
            if contacts.is_empty() {
                return Err(MessageGenerationError::EmptyContacts);
            }
            if contacts.len() == 1 {
                let c = &contacts[0];
                m.contact_message = Some(
                    ContactMessage {
                        display_name: c.display_name.clone().or(display_name),
                        vcard: Some(c.vcard.clone()),
                        ..Default::default()
                    }
                    .into(),
                );
            } else {
                let list: Vec<ContactMessage> = contacts
                    .into_iter()
                    .map(|c| ContactMessage {
                        display_name: c.display_name,
                        vcard: Some(c.vcard),
                        ..Default::default()
                    })
                    .collect();
                m.contacts_array_message = Some(
                    ContactsArrayMessage {
                        display_name,
                        contacts: list,
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }
        AnyMessageContent::Location(loc) => {
            m.location_message = Some(
                LocationMessage {
                    degrees_latitude: Some(loc.degrees_latitude),
                    degrees_longitude: Some(loc.degrees_longitude),
                    name: loc.name,
                    address: loc.address,
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::React(react) => {
            let ts = react
                .sender_timestamp_ms
                .unwrap_or_else(|| now_millis() as i64);
            m.reaction_message = Some(
                ReactionMessage {
                    key: Some(react.key.to_proto()),
                    text: Some(react.text),
                    sender_timestamp_ms: Some(ts),
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::Delete(key) => {
            m.protocol_message = Some(
                ProtocolMessage {
                    key: Some(key.to_proto()),
                    r#type: Some(protocol_message::Type::Revoke as i32),
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::Forward { message, force } => {
            m = generate_forward_message_content(&message, force)?;
        }
        AnyMessageContent::DisappearingMessagesInChat(exp) => {
            m = prepare_disappearing_message_setting_content(exp);
        }
        AnyMessageContent::GroupInvite(invite) => {
            m.group_invite_message = Some(
                GroupInviteMessage {
                    group_jid: Some(invite.jid),
                    invite_code: Some(invite.invite_code),
                    invite_expiration: Some(invite.invite_expiration),
                    group_name: Some(invite.subject),
                    caption: Some(invite.text),
                    jpeg_thumbnail: invite.jpeg_thumbnail,
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::Pin(pin) => {
            m.pin_in_chat_message = Some(
                PinInChatMessage {
                    key: Some(pin.key.to_proto()),
                    r#type: Some(pin.pin_type),
                    sender_timestamp_ms: Some(now_millis() as i64),
                }
                .into(),
            );
            let duration = if pin.pin_type == 1 {
                pin.time_secs.unwrap_or(86_400)
            } else {
                0
            };
            m.message_context_info = Some(
                MessageContextInfo {
                    message_add_on_duration_in_secs: Some(duration),
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::Poll(poll) => {
            if poll.selectable_count as usize > poll.values.len() {
                return Err(MessageGenerationError::InvalidPollSelectableCount(
                    poll.values.len(),
                ));
            }
            let secret = poll.message_secret.unwrap_or_else(|| {
                let mut s = vec![0u8; 32];
                OsRng.fill_bytes(&mut s);
                s
            });
            m.message_context_info = Some(
                MessageContextInfo {
                    message_secret: Some(secret),
                    ..Default::default()
                }
                .into(),
            );
            let poll_msg = PollCreationMessage {
                name: Some(poll.name),
                selectable_options_count: Some(poll.selectable_count),
                options: poll
                    .values
                    .into_iter()
                    .map(|name| poll_creation_message::Option {
                        option_name: Some(name),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            if poll.to_announcement_group {
                m.poll_creation_message_v2 = Some(poll_msg.into());
            } else if poll.selectable_count == 1 {
                m.poll_creation_message_v3 = Some(poll_msg.into());
            } else {
                m.poll_creation_message = Some(poll_msg.into());
            }
        }
        AnyMessageContent::SharePhoneNumber => {
            m.protocol_message = Some(
                ProtocolMessage {
                    r#type: Some(protocol_message::Type::SharePhoneNumber as i32),
                    ..Default::default()
                }
                .into(),
            );
        }
        AnyMessageContent::RequestPhoneNumber => {
            m.request_phone_number_message = Some(RequestPhoneNumberMessage::default().into());
        }
        AnyMessageContent::Raw(raw) => {
            m = raw;
        }
    }

    if options.view_once {
        m = Message {
            view_once_message: Some(
                FutureProofMessage {
                    message: Some(m.into()),
                }
                .into(),
            ),
            ..Default::default()
        };
    }

    if !options.mentions.is_empty() {
        let mentions = options.mentions.clone();
        attach_context_info(&mut m, |ci| {
            ci.mentioned_jid = mentions;
        });
    }

    if let Some(ref edit_key) = options.edit {
        m = Message {
            protocol_message: Some(
                ProtocolMessage {
                    key: Some(edit_key.to_proto()),
                    edited_message: Some(m.into()),
                    timestamp_ms: Some(now_millis() as i64),
                    r#type: Some(protocol_message::Type::MessageEdit as i32),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
    }

    if let Some(ref extra_ci) = options.context_info {
        let extra = extra_ci.clone();
        attach_context_info(&mut m, |ci| {
            if !extra.mentioned_jid.is_empty() {
                ci.mentioned_jid = extra.mentioned_jid;
            }
            if extra.stanza_id.is_some() {
                ci.stanza_id = extra.stanza_id;
            }
            if extra.participant.is_some() {
                ci.participant = extra.participant;
            }
            if extra.remote_jid.is_some() {
                ci.remote_jid = extra.remote_jid;
            }
            if extra.quoted_message.is_some() {
                ci.quoted_message = extra.quoted_message;
            }
            if extra.expiration.is_some() {
                ci.expiration = extra.expiration;
            }
            if extra.forwarding_score.is_some() {
                ci.forwarding_score = extra.forwarding_score;
            }
            if extra.is_forwarded.is_some() {
                ci.is_forwarded = extra.is_forwarded;
            }
        });
    }

    Ok(m)
}

pub fn generate_wa_message_from_content(
    jid: &str,
    mut message: Message,
    options: &MessageGenerationOptions,
) -> WaMessage {
    let timestamp = options.timestamp.unwrap_or_else(unix_timestamp_seconds);
    let content_type = get_content_type(&message);

    if let Some(ref quoted) = options.quoted {
        if !is_jid_newsletter(Some(jid)) {
            let participant = if quoted.key.from_me == Some(true) {
                options.user_jid.clone()
            } else {
                quoted
                    .participant
                    .clone()
                    .or_else(|| quoted.key.participant.clone())
                    .or_else(|| quoted.key.remote_jid.clone())
            };

            let quoted_msg = quoted
                .message
                .as_ref()
                .map(normalize_message_content)
                .map(|mut qm| {
                    attach_context_info(&mut qm, |ci| {
                        *ci = ContextInfo::default();
                    });
                    qm
                });

            let normalized_participant = participant.as_deref().map(|p| jid_normalized_user(Some(p)));
            let stanza_id = quoted.key.id.clone();
            let remote_jid_diff = if quoted.key.remote_jid.as_deref() != Some(jid) {
                quoted.key.remote_jid.clone()
            } else {
                None
            };

            attach_context_info(&mut message, |ci| {
                ci.participant = normalized_participant;
                ci.stanza_id = stanza_id;
                ci.quoted_message = quoted_msg.map(Into::into);
                if remote_jid_diff.is_some() {
                    ci.remote_jid = remote_jid_diff;
                }
            });
        }
    }

    if let Some(exp) = options.ephemeral_expiration {
        if exp > 0
            && content_type != Some("protocolMessage")
            && content_type != Some("ephemeralMessage")
            && !is_jid_newsletter(Some(jid))
        {
            let final_exp = if exp == 0 { WA_DEFAULT_EPHEMERAL } else { exp };
            attach_context_info(&mut message, |ci| {
                ci.expiration = Some(final_exp);
            });
        }
    }

    let msg_id = options
        .message_id
        .clone()
        .unwrap_or_else(|| generate_message_id_v2(options.user_jid.as_deref()));

    let participant = if is_jid_group(Some(jid)) || is_jid_status_broadcast(jid) {
        options.user_jid.clone()
    } else {
        None
    };

    WaMessage {
        key: WaMessageKey {
            remote_jid: Some(jid.to_string()),
            from_me: Some(true),
            id: Some(msg_id),
            ..Default::default()
        },
        message: Some(message),
        message_timestamp: Some(timestamp),
        participant,
        status: Some(web_message_info::Status::Pending as i32),
        ..Default::default()
    }
}

pub fn generate_wa_message(
    jid: &str,
    content: AnyMessageContent,
    options: &MessageGenerationOptions,
) -> Result<WaMessage, MessageGenerationError> {
    let proto_msg = generate_wa_message_content(content, options)?;
    Ok(generate_wa_message_from_content(jid, proto_msg, options))
}

pub fn get_content_type(content: &Message) -> Option<&'static str> {
    if content.conversation.is_some() {
        return Some("conversation");
    }
    if content.extended_text_message.is_some() {
        return Some("extendedTextMessage");
    }
    if content.image_message.is_some() {
        return Some("imageMessage");
    }
    if content.video_message.is_some() {
        return Some("videoMessage");
    }
    if content.audio_message.is_some() {
        return Some("audioMessage");
    }
    if content.document_message.is_some() {
        return Some("documentMessage");
    }
    if content.sticker_message.is_some() {
        return Some("stickerMessage");
    }
    if content.contact_message.is_some() {
        return Some("contactMessage");
    }
    if content.contacts_array_message.is_some() {
        return Some("contactsArrayMessage");
    }
    if content.location_message.is_some() {
        return Some("locationMessage");
    }
    if content.reaction_message.is_some() {
        return Some("reactionMessage");
    }
    if content.protocol_message.is_some() {
        return Some("protocolMessage");
    }
    if content.ephemeral_message.is_some() {
        return Some("ephemeralMessage");
    }
    if content.view_once_message.is_some() {
        return Some("viewOnceMessage");
    }
    if content.view_once_message_v2.is_some() {
        return Some("viewOnceMessageV2");
    }
    if content.group_invite_message.is_some() {
        return Some("groupInviteMessage");
    }
    if content.pin_in_chat_message.is_some() {
        return Some("pinInChatMessage");
    }
    if content.poll_creation_message.is_some() {
        return Some("pollCreationMessage");
    }
    if content.poll_creation_message_v2.is_some() {
        return Some("pollCreationMessageV2");
    }
    if content.poll_creation_message_v3.is_some() {
        return Some("pollCreationMessageV3");
    }
    if content.ptv_message.is_some() {
        return Some("ptvMessage");
    }
    if content.buttons_message.is_some() {
        return Some("buttonsMessage");
    }
    if content.template_message.is_some() {
        return Some("templateMessage");
    }
    if content.list_message.is_some() {
        return Some("listMessage");
    }
    if content.list_response_message.is_some() {
        return Some("listResponseMessage");
    }
    if content.buttons_response_message.is_some() {
        return Some("buttonsResponseMessage");
    }
    if content.template_button_reply_message.is_some() {
        return Some("templateButtonReplyMessage");
    }
    if content.event_message.is_some() {
        return Some("eventMessage");
    }
    if content.album_message.is_some() {
        return Some("albumMessage");
    }
    if content.request_phone_number_message.is_some() {
        return Some("requestPhoneNumberMessage");
    }
    None
}

fn unwrap_future_proof(content: &Message) -> Option<&Message> {
    let wrapper: Option<&FutureProofMessage> = content
        .ephemeral_message
        .as_ref()
        .map(|w| Borrow::borrow(w))
        .or_else(|| content.view_once_message.as_ref().map(|w| Borrow::borrow(w)))
        .or_else(|| {
            content
                .document_with_caption_message
                .as_ref()
                .map(|w| Borrow::borrow(w))
        })
        .or_else(|| {
            content
                .view_once_message_v2
                .as_ref()
                .map(|w| Borrow::borrow(w))
        })
        .or_else(|| {
            content
                .view_once_message_v2_extension
                .as_ref()
                .map(|w| Borrow::borrow(w))
        })
        .or_else(|| content.edited_message.as_ref().map(|w| Borrow::borrow(w)))
        .or_else(|| {
            content
                .associated_child_message
                .as_ref()
                .map(|w| Borrow::borrow(w))
        })
        .or_else(|| {
            content
                .group_status_message
                .as_ref()
                .map(|w| Borrow::borrow(w))
        })
        .or_else(|| {
            content
                .group_status_message_v2
                .as_ref()
                .map(|w| Borrow::borrow(w))
        });

    wrapper.and_then(|w| w.message.as_ref().map(|m| Borrow::borrow(m)))
}

pub fn normalize_message_content(content: &Message) -> Message {
    let mut current = content;
    for _ in 0..5 {
        if let Some(inner) = unwrap_future_proof(current) {
            current = inner;
        } else {
            break;
        }
    }
    current.clone()
}

pub fn extract_message_content(content: &Message) -> Message {
    normalize_message_content(content)
}

pub fn get_device(id: &str) -> &'static str {
    let len = id.len();
    if id.starts_with("3A") && len == 20 {
        "ios"
    } else if id.starts_with("3E") && len == 22 {
        "web"
    } else if len == 21 || len == 32 {
        "android"
    } else if id.starts_with("3F") || len == 18 {
        "desktop"
    } else {
        "unknown"
    }
}

pub fn update_message_with_receipt(msg: &mut WaMessage, receipt: UserReceipt) {
    if let Some(existing) = msg
        .user_receipt
        .iter_mut()
        .find(|r| r.user_jid == receipt.user_jid)
    {
        *existing = receipt;
    } else {
        msg.user_receipt.push(receipt);
    }
}

pub fn update_message_with_reaction(msg: &mut WaMessage, mut reaction: Reaction) {
    let author_id = get_proto_key_author(reaction.key.as_ref(), None);
    msg.reactions
        .retain(|r| get_proto_key_author(r.key.as_ref(), None) != author_id);
    if reaction.text.is_none() {
        reaction.text = Some(String::new());
    }
    msg.reactions.push(reaction);
}

pub fn update_message_with_poll_update(msg: &mut WaMessage, update: PollUpdate) {
    let author_id = get_proto_key_author(update.poll_update_message_key.as_ref(), None);
    msg.poll_updates
        .retain(|r| get_proto_key_author(r.poll_update_message_key.as_ref(), None) != author_id);
    let has_votes = update
        .vote
        .as_ref()
        .is_some_and(|v| !v.selected_options.is_empty());
    if has_votes {
        msg.poll_updates.push(update);
    }
}

pub fn get_aggregate_votes_in_poll_message(
    msg: &WaMessage,
    me_id: Option<&str>,
) -> Vec<VoteAggregation> {
    let options = msg
        .message
        .as_ref()
        .and_then(|m| {
            m.poll_creation_message
                .as_ref()
                .map(|p| {
                    let r: &PollCreationMessage = Borrow::borrow(p);
                    &r.options
                })
                .or_else(|| {
                    m.poll_creation_message_v2.as_ref().map(|p| {
                        let r: &PollCreationMessage = Borrow::borrow(p);
                        &r.options
                    })
                })
                .or_else(|| {
                    m.poll_creation_message_v3.as_ref().map(|p| {
                        let r: &PollCreationMessage = Borrow::borrow(p);
                        &r.options
                    })
                })
        })
        .cloned()
        .unwrap_or_default();

    let mut vote_map: HashMap<Vec<u8>, VoteAggregation> = HashMap::new();
    for opt in options {
        let name = opt.option_name.unwrap_or_default();
        let hash = sha256(name.as_bytes());
        vote_map.insert(
            hash,
            VoteAggregation {
                name,
                voters: Vec::new(),
            },
        );
    }

    for update in &msg.poll_updates {
        let Some(ref vote) = update.vote else {
            continue;
        };
        let voter = get_proto_key_author(update.poll_update_message_key.as_ref(), me_id);
        for opt_hash in &vote.selected_options {
            let entry = vote_map
                .entry(opt_hash.clone())
                .or_insert_with(|| VoteAggregation {
                    name: "Unknown".to_string(),
                    voters: Vec::new(),
                });
            entry.voters.push(voter.clone());
        }
    }

    vote_map.into_values().collect()
}

pub fn aggregate_message_keys_not_from_me(keys: &[WaMessageKey]) -> Vec<AggregatedMessageKeys> {
    let mut map: HashMap<String, AggregatedMessageKeys> = HashMap::new();
    for key in keys {
        if key.from_me == Some(true) {
            continue;
        }
        let Some(jid) = key.remote_jid.clone() else {
            continue;
        };
        let Some(id) = key.id.clone() else {
            continue;
        };
        let uq_key = format!("{}:{}", jid, key.participant.as_deref().unwrap_or(""));
        let entry = map.entry(uq_key).or_insert_with(|| AggregatedMessageKeys {
            jid,
            participant: key.participant.clone(),
            message_ids: Vec::new(),
        });
        entry.message_ids.push(id);
    }
    map.into_values().collect()
}

pub fn assert_media_content(content: &Message) -> Result<MediaContent, MessageGenerationError> {
    let extracted = extract_message_content(content);
    if let Some(m) = extracted.document_message {
        let inner: &DocumentMessage = Borrow::borrow(&m);
        return Ok(MediaContent::Document(inner.clone()));
    }
    if let Some(m) = extracted.image_message {
        let inner: &ImageMessage = Borrow::borrow(&m);
        return Ok(MediaContent::Image(inner.clone()));
    }
    if let Some(m) = extracted.video_message {
        let inner: &VideoMessage = Borrow::borrow(&m);
        return Ok(MediaContent::Video(inner.clone()));
    }
    if let Some(m) = extracted.audio_message {
        let inner: &AudioMessage = Borrow::borrow(&m);
        return Ok(MediaContent::Audio(inner.clone()));
    }
    if let Some(m) = extracted.sticker_message {
        let inner: &StickerMessage = Borrow::borrow(&m);
        return Ok(MediaContent::Sticker(inner.clone()));
    }
    Err(MessageGenerationError::NotAMediaMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_text_with_mentions_quote_and_ephemeral() {
        let quoted = WaMessage {
            key: WaMessageKey {
                remote_jid: Some("573001111111@s.whatsapp.net".to_string()),
                from_me: Some(false),
                id: Some("QUOTED_123".to_string()),
                ..Default::default()
            },
            message: Some(Message {
                conversation: Some("mensaje original".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let opts = MessageGenerationOptions {
            user_jid: Some("573002222222@s.whatsapp.net".to_string()),
            mentions: vec!["573001111111@s.whatsapp.net".to_string()],
            quoted: Some(Box::new(quoted)),
            ephemeral_expiration: Some(86_400),
            background_color: Some("#112233".to_string()),
            ..Default::default()
        };

        let msg = generate_wa_message(
            "573001111111@s.whatsapp.net",
            AnyMessageContent::Text("Hola @573001111111".to_string()),
            &opts,
        )
        .unwrap();

        assert_eq!(msg.key.from_me, Some(true));
        let proto_msg = msg.message.as_ref().unwrap();
        assert_eq!(get_content_type(proto_msg), Some("extendedTextMessage"));
        let ext: &ExtendedTextMessage = Borrow::borrow(proto_msg.extended_text_message.as_ref().unwrap());
        assert_eq!(ext.background_argb, Some(0xFF112233));
        let ci: &ContextInfo = Borrow::borrow(ext.context_info.as_ref().unwrap());
        assert_eq!(ci.stanza_id.as_deref(), Some("QUOTED_123"));
        assert_eq!(ci.expiration, Some(86_400));
        assert_eq!(ci.mentioned_jid, vec!["573001111111@s.whatsapp.net"]);
    }

    #[test]
    fn test_normalize_forward_and_helpers() {
        let wrapped = Message {
            view_once_message: Some(
                FutureProofMessage {
                    message: Some(
                        Message {
                            conversation: Some("secreto".to_string()),
                            ..Default::default()
                        }
                        .into(),
                    ),
                }
                .into(),
            ),
            ..Default::default()
        };
        let unwrapped = normalize_message_content(&wrapped);
        assert_eq!(unwrapped.conversation.as_deref(), Some("secreto"));

        let wa_msg = WaMessage {
            key: WaMessageKey {
                from_me: Some(false),
                ..Default::default()
            },
            message: Some(wrapped),
            ..Default::default()
        };
        let forwarded = generate_forward_message_content(&wa_msg, false).unwrap();
        let ext: &ExtendedTextMessage = Borrow::borrow(forwarded.extended_text_message.as_ref().unwrap());
        assert_eq!(ext.text.as_deref(), Some("secreto"));
        let ci: &ContextInfo = Borrow::borrow(ext.context_info.as_ref().unwrap());
        assert_eq!(ci.forwarding_score, Some(1));
        assert_eq!(ci.is_forwarded, Some(true));

        assert_eq!(
            extract_url_from_text("mira https://github.com/LuferOS/Baileys-Rust hoy"),
            Some("https://github.com/LuferOS/Baileys-Rust")
        );
        assert_eq!(get_device("3EB0123456789012345678"), "web");
        assert_eq!(get_device("3A123456789012345678"), "ios");
    }

    #[test]
    fn test_poll_and_aggregate_keys() {
        let poll_msg = generate_wa_message(
            "1203630001@g.us",
            AnyMessageContent::Poll(PollInput {
                name: "Lenguaje".to_string(),
                values: vec!["Rust".to_string(), "TS".to_string()],
                selectable_count: 1,
                to_announcement_group: false,
                message_secret: None,
            }),
            &MessageGenerationOptions::default(),
        )
        .unwrap();
        assert_eq!(
            get_content_type(poll_msg.message.as_ref().unwrap()),
            Some("pollCreationMessageV3")
        );

        let keys = vec![
            WaMessageKey {
                remote_jid: Some("1203630001@g.us".to_string()),
                participant: Some("573001@s.whatsapp.net".to_string()),
                id: Some("M1".to_string()),
                from_me: Some(false),
                ..Default::default()
            },
            WaMessageKey {
                remote_jid: Some("1203630001@g.us".to_string()),
                participant: Some("573001@s.whatsapp.net".to_string()),
                id: Some("M2".to_string()),
                from_me: Some(false),
                ..Default::default()
            },
            WaMessageKey {
                remote_jid: Some("1203630001@g.us".to_string()),
                id: Some("M3".to_string()),
                from_me: Some(true),
                ..Default::default()
            },
        ];
        let agg = aggregate_message_keys_not_from_me(&keys);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].message_ids, vec!["M1", "M2"]);
    }
}
