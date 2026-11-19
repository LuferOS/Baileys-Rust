use crate::defaults::MediaType;
use crate::proto::history_sync::HistorySyncType;
use crate::proto::message::{HistorySyncNotification, ProtocolMessage};
use crate::proto::{
    web_message_info, Conversation, HistorySync, HistorySyncMsg, Message, PastParticipants,
    WebMessageInfo,
};
use crate::types::LidMapping;
use crate::utils::messages::normalize_message_content;
use crate::utils::messages_media::{
    download_content_from_message, DownloadableMessage, MediaDownloadOptions, MediaError,
};
use crate::wa_binary::{is_hosted_lid_user, is_hosted_pn_user, is_lid_user, is_pn_user};
use flate2::read::ZlibDecoder;
use prost::Message as ProstMessage;
use std::borrow::Borrow;
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("media error: {0}")]
    Media(#[from] MediaError),
    #[error("zlib inflate error: {0}")]
    Inflate(#[from] std::io::Error),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryContact {
    pub id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub notify: Option<String>,
    pub verified_name: Option<String>,
    pub lid: Option<String>,
    pub phone_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryChat {
    pub conversation: Conversation,
    pub last_message_recv_timestamp: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessedHistory {
    pub chats: Vec<HistoryChat>,
    pub contacts: Vec<HistoryContact>,
    pub messages: Vec<WebMessageInfo>,
    pub lid_pn_mappings: Vec<LidMapping>,
    pub past_participants: Vec<PastParticipants>,
    pub sync_type: i32,
    pub progress: Option<u32>,
}

fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, HistoryError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn extract_pn_from_messages(messages: &[HistorySyncMsg]) -> Option<String> {
    for msg_item in messages {
        let Some(ref message) = msg_item.message else {
            continue;
        };
        let from_me = message.key.as_ref().and_then(|k| k.from_me) == Some(true);
        if !from_me || message.user_receipt.is_empty() {
            continue;
        }
        let user_jid = &message.user_receipt[0].user_jid;
        if !user_jid.is_empty()
            && (is_pn_user(Some(user_jid)) || is_hosted_pn_user(Some(user_jid)))
        {
            return Some(user_jid.clone());
        }
    }
    None
}

pub async fn download_history(
    msg: &HistorySyncNotification,
    opts: &MediaDownloadOptions,
) -> Result<HistorySync, HistoryError> {
    let downloadable = DownloadableMessage {
        media_key: msg.media_key.clone(),
        direct_path: msg.direct_path.clone(),
        url: None,
    };
    let compressed = download_content_from_message(&downloadable, MediaType::MdMsgHist, opts).await?;
    let inflated = inflate_zlib(&compressed)?;
    Ok(HistorySync::decode(inflated.as_slice())?)
}

pub fn process_history_message(item: &HistorySync) -> ProcessedHistory {
    let mut messages = Vec::new();
    let mut contacts = Vec::new();
    let mut chats = Vec::new();
    let mut lid_pn_mappings = Vec::new();

    for m in &item.phone_number_to_lid_mappings {
        if let (Some(lid), Some(pn)) = (m.lid_jid.as_ref(), m.pn_jid.as_ref()) {
            if !lid.is_empty() && !pn.is_empty() {
                lid_pn_mappings.push(LidMapping {
                    lid: lid.clone(),
                    pn: pn.clone(),
                });
            }
        }
    }

    let is_chat_sync = item.sync_type == HistorySyncType::InitialBootstrap as i32
        || item.sync_type == HistorySyncType::Recent as i32
        || item.sync_type == HistorySyncType::Full as i32
        || item.sync_type == HistorySyncType::OnDemand as i32;

    if is_chat_sync {
        for raw_chat in &item.conversations {
            let mut chat = raw_chat.clone();
            let chat_id = chat.id.clone();

            let name = chat
                .display_name
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| chat.name.clone().filter(|s| !s.is_empty()))
                .or_else(|| chat.username.clone().filter(|s| !s.is_empty()));

            let lid = chat
                .lid_jid
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| chat.account_lid.clone().filter(|s| !s.is_empty()));

            contacts.push(HistoryContact {
                id: chat_id.clone(),
                name,
                username: chat.username.clone().filter(|s| !s.is_empty()),
                lid,
                phone_number: chat.pn_jid.clone().filter(|s| !s.is_empty()),
                ..Default::default()
            });

            let is_lid = is_lid_user(Some(&chat_id)) || is_hosted_lid_user(Some(&chat_id));
            let is_pn = is_pn_user(Some(&chat_id)) || is_hosted_pn_user(Some(&chat_id));

            if is_lid {
                if let Some(ref pn) = chat.pn_jid.as_ref().filter(|s| !s.is_empty()) {
                    lid_pn_mappings.push(LidMapping {
                        lid: chat_id.clone(),
                        pn: (*pn).clone(),
                    });
                } else if let Some(pn_from_receipt) = extract_pn_from_messages(&chat.messages) {
                    lid_pn_mappings.push(LidMapping {
                        lid: chat_id.clone(),
                        pn: pn_from_receipt,
                    });
                }
            } else if is_pn {
                if let Some(ref lid_jid) = chat.lid_jid.as_ref().filter(|s| !s.is_empty()) {
                    lid_pn_mappings.push(LidMapping {
                        lid: (*lid_jid).clone(),
                        pn: chat_id.clone(),
                    });
                }
            }

            let msgs = std::mem::take(&mut chat.messages);
            let mut last_message_recv_timestamp = None;

            for hist_msg in msgs {
                let Some(message) = hist_msg.message else {
                    continue;
                };

                if chat.messages.is_empty() {
                    chat.messages.push(HistorySyncMsg {
                        message: Some(message.clone()),
                        msg_order_id: hist_msg.msg_order_id,
                    });
                }

                let from_me = message.key.as_ref().and_then(|k| k.from_me) == Some(true);
                if !from_me && last_message_recv_timestamp.is_none() {
                    last_message_recv_timestamp = message.message_timestamp;
                }

                let is_biz_stub = message.message_stub_type
                    == Some(web_message_info::StubType::BizPrivacyModeToBsp as i32)
                    || message.message_stub_type
                        == Some(web_message_info::StubType::BizPrivacyModeToFb as i32);

                if is_biz_stub {
                    if let Some(verified_name) = message.message_stub_parameters.first() {
                        if !verified_name.is_empty() {
                            let contact_id = message
                                .key
                                .as_ref()
                                .and_then(|k| {
                                    k.participant.clone().or_else(|| k.remote_jid.clone())
                                })
                                .unwrap_or_default();
                            contacts.push(HistoryContact {
                                id: contact_id,
                                verified_name: Some(verified_name.clone()),
                                ..Default::default()
                            });
                        }
                    }
                }

                messages.push(message);
            }

            chats.push(HistoryChat {
                conversation: chat,
                last_message_recv_timestamp,
            });
        }
    } else if item.sync_type == HistorySyncType::PushName as i32 {
        for c in &item.pushnames {
            if let Some(ref id) = c.id {
                contacts.push(HistoryContact {
                    id: id.clone(),
                    notify: c.pushname.clone(),
                    ..Default::default()
                });
            }
        }
    }

    ProcessedHistory {
        chats,
        contacts,
        messages,
        lid_pn_mappings,
        past_participants: item.past_participants.clone(),
        sync_type: item.sync_type,
        progress: item.progress,
    }
}

pub async fn download_and_process_history_sync_notification(
    msg: &HistorySyncNotification,
    opts: &MediaDownloadOptions,
) -> Result<ProcessedHistory, HistoryError> {
    let history_msg = if let Some(ref inline_payload) = msg.initial_hist_bootstrap_inline_payload {
        let inflated = inflate_zlib(inline_payload)?;
        HistorySync::decode(inflated.as_slice())?
    } else {
        download_history(msg, opts).await?
    };

    Ok(process_history_message(&history_msg))
}

pub fn get_history_msg(message: &Message) -> Option<HistorySyncNotification> {
    let normalized = normalize_message_content(message);
    let proto_msg: &ProtocolMessage = normalized
        .protocol_message
        .as_ref()
        .map(|p| Borrow::borrow(p))?;
    proto_msg.history_sync_notification.as_ref().map(|h| {
        let inner: &HistorySyncNotification = Borrow::borrow(h);
        inner.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::FutureProofMessage;
    use crate::proto::{MessageKey, PhoneNumberToLidMapping, Pushname, UserReceipt};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[tokio::test]
    async fn test_inline_history_sync_and_lid_extraction() {
        let history = HistorySync {
            sync_type: HistorySyncType::InitialBootstrap as i32,
            progress: Some(100),
            phone_number_to_lid_mappings: vec![PhoneNumberToLidMapping {
                pn_jid: Some("573001111111@s.whatsapp.net".to_string()),
                lid_jid: Some("111111@lid".to_string()),
            }],
            conversations: vec![Conversation {
                id: "222222@lid".to_string(),
                name: Some("Bob".to_string()),
                messages: vec![
                    HistorySyncMsg {
                        message: Some(WebMessageInfo {
                            key: Some(MessageKey {
                                remote_jid: Some("222222@lid".to_string()),
                                from_me: Some(true),
                                id: Some("M1".to_string()),
                                participant: None,
                            }),
                            message_timestamp: Some(1700000010),
                            user_receipt: vec![UserReceipt {
                                user_jid: "573002222222@s.whatsapp.net".to_string(),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                        msg_order_id: Some(2),
                    },
                    HistorySyncMsg {
                        message: Some(WebMessageInfo {
                            key: Some(MessageKey {
                                remote_jid: Some("222222@lid".to_string()),
                                from_me: Some(false),
                                id: Some("M0".to_string()),
                                participant: None,
                            }),
                            message_timestamp: Some(1700000005),
                            ..Default::default()
                        }),
                        msg_order_id: Some(1),
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&history.encode_to_vec()).unwrap();
        let compressed = encoder.finish().unwrap();

        let notif = HistorySyncNotification {
            initial_hist_bootstrap_inline_payload: Some(compressed),
            sync_type: Some(HistorySyncType::InitialBootstrap as i32),
            ..Default::default()
        };

        let processed = download_and_process_history_sync_notification(
            &notif,
            &MediaDownloadOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(processed.chats.len(), 1);
        assert_eq!(processed.chats[0].conversation.messages.len(), 1);
        assert_eq!(
            processed.chats[0].last_message_recv_timestamp,
            Some(1700000005)
        );
        assert_eq!(processed.messages.len(), 2);
        assert_eq!(processed.lid_pn_mappings.len(), 2);
        assert_eq!(
            processed.lid_pn_mappings[1].pn,
            "573002222222@s.whatsapp.net"
        );
    }

    #[test]
    fn test_push_name_sync_and_get_history_msg() {
        let push_sync = HistorySync {
            sync_type: HistorySyncType::PushName as i32,
            pushnames: vec![Pushname {
                id: Some("573009999999@s.whatsapp.net".to_string()),
                pushname: Some("Luis".to_string()),
            }],
            ..Default::default()
        };
        let processed = process_history_message(&push_sync);
        assert_eq!(processed.contacts.len(), 1);
        assert_eq!(processed.contacts[0].notify.as_deref(), Some("Luis"));

        let wrapped = Message {
            ephemeral_message: Some(
                FutureProofMessage {
                    message: Some(
                        Message {
                            protocol_message: Some(
                                ProtocolMessage {
                                    history_sync_notification: Some(
                                        HistorySyncNotification {
                                            progress: Some(50),
                                            ..Default::default()
                                        }
                                        .into(),
                                    ),
                                    ..Default::default()
                                }
                                .into(),
                            ),
                            ..Default::default()
                        }
                        .into(),
                    ),
                }
                .into(),
            ),
            ..Default::default()
        };
        let hist = get_history_msg(&wrapped).unwrap();
        assert_eq!(hist.progress, Some(50));
    }
}
