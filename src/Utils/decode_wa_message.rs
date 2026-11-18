use crate::proto::{verified_name_certificate, web_message_info, Message, VerifiedNameCertificate};
use crate::signal::LibSignalRepository;
use crate::types::{
    AddressingContext, LidMapping, MessageCipherType, MessageType, WaMessage, WaMessageKey,
};
use crate::utils::generics::unpad_random_max_16;
use crate::wa_binary::{
    are_jids_same_user, is_hosted_lid_user, is_hosted_pn_user, is_jid_broadcast, is_jid_group,
    is_jid_meta_ai, is_jid_newsletter, is_jid_status_broadcast, is_lid_user, is_pn_user,
    BinaryNode, BinaryNodeData,
};
use prost::Message as ProstMessage;
use std::borrow::Borrow;
use thiserror::Error;

pub const NO_MESSAGE_FOUND_ERROR_TEXT: &str = "Message absent from node";
pub const MISSING_KEYS_ERROR_TEXT: &str = "Key used already or never filled";
pub const ACCOUNT_RESTRICTED_TEXT: &str = "Your account has been restricted";

pub const DECRYPTION_RETRY_MAX_RETRIES: u32 = 3;
pub const DECRYPTION_RETRY_BASE_DELAY_MS: u64 = 100;
pub const SESSION_RECORD_ERROR_PATTERNS: [&str; 3] = [
    "No session record",
    "SessionError: No session record",
    "no open session",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NackReason {
    SenderReachoutTimelocked = 463,
    ParsingError = 487,
    UnrecognizedStanza = 488,
    UnrecognizedStanzaClass = 489,
    UnrecognizedStanzaType = 490,
    InvalidProtobuf = 491,
    InvalidHostedCompanionStanza = 493,
    MissingMessageSecret = 495,
    SignalErrorOldCounter = 496,
    MessageDeletedOnPeer = 499,
    UnhandledError = 500,
    UnsupportedAdminRevoke = 550,
    UnsupportedLidGroup = 551,
    DbOperationFailed = 552,
}

pub const SERVER_ERROR_MESSAGE_ACCOUNT_RESTRICTION: &str = "463";
pub const SERVER_ERROR_SMAX_INVALID: &str = "479";

#[derive(Debug, Error)]
pub enum DecodeMessageError {
    #[error("invalid message stanza: missing {0} attribute")]
    MissingAttribute(&'static str),
    #[error("recipient present, but msg not from me")]
    InvalidRecipientNotFromMe,
    #[error("no participant in group or broadcast message")]
    MissingParticipant,
    #[error("unknown message type from: {0}")]
    UnknownMessageType(String),
}

pub struct DecodedMessageNode {
    pub full_message: WaMessage,
    pub author: String,
    pub sender: String,
    pub category: Option<String>,
}

pub async fn get_decryption_jid(sender: &str, repository: &LibSignalRepository) -> String {
    if is_lid_user(Some(sender)) || is_hosted_lid_user(Some(sender)) {
        return sender.to_string();
    }
    repository
        .lid_mapping
        .get_lid_for_pn(sender)
        .await
        .unwrap_or_else(|| sender.to_string())
}

async fn store_mapping_from_envelope(
    stanza: &BinaryNode,
    sender: &str,
    repository: &LibSignalRepository,
    decryption_jid: &str,
) {
    let ctx = extract_addressing_context(stanza);
    if let Some(sender_alt) = ctx.sender_alt {
        if is_lid_user(Some(&sender_alt))
            && is_pn_user(Some(sender))
            && decryption_jid == sender
        {
            let _ = repository
                .lid_mapping
                .store_lid_pn_mappings(&[LidMapping {
                    lid: sender_alt.clone(),
                    pn: sender.to_string(),
                }])
                .await;
            let _ = repository.migrate_session(sender, &sender_alt).await;
        }
    }
}

pub fn extract_addressing_context(stanza: &BinaryNode) -> AddressingContext {
    let sender = stanza
        .attrs
        .get("participant")
        .or_else(|| stanza.attrs.get("from"));

    let addressing_mode = stanza
        .attrs
        .get("addressing_mode")
        .cloned()
        .unwrap_or_else(|| {
            if sender.is_some_and(|s| s.ends_with("lid")) {
                "lid".to_string()
            } else {
                "pn".to_string()
            }
        });

    let (sender_alt, recipient_alt) = if addressing_mode == "lid" {
        (
            stanza
                .attrs
                .get("participant_pn")
                .or_else(|| stanza.attrs.get("sender_pn"))
                .or_else(|| stanza.attrs.get("peer_recipient_pn"))
                .cloned(),
            stanza.attrs.get("recipient_pn").cloned(),
        )
    } else {
        (
            stanza
                .attrs
                .get("participant_lid")
                .or_else(|| stanza.attrs.get("sender_lid"))
                .or_else(|| stanza.attrs.get("peer_recipient_lid"))
                .cloned(),
            stanza.attrs.get("recipient_lid").cloned(),
        )
    };

    AddressingContext {
        addressing_mode,
        sender_alt,
        recipient_alt,
    }
}

pub fn decode_message_node(
    stanza: &BinaryNode,
    me_id: &str,
    me_lid: &str,
) -> Result<DecodedMessageNode, DecodeMessageError> {
    let msg_id = stanza
        .attrs
        .get("id")
        .cloned()
        .ok_or(DecodeMessageError::MissingAttribute("id"))?;
    let from = stanza
        .attrs
        .get("from")
        .cloned()
        .ok_or(DecodeMessageError::MissingAttribute("from"))?;
    let participant = stanza.attrs.get("participant").cloned();
    let recipient = stanza.attrs.get("recipient").cloned();

    let addressing_context = extract_addressing_context(stanza);

    let is_me = |jid: &str| are_jids_same_user(Some(jid), Some(me_id));
    let is_me_lid = |jid: &str| !me_lid.is_empty() && are_jids_same_user(Some(jid), Some(me_lid));

    let msg_type: MessageType;
    let chat_id: String;
    let author: String;
    let mut from_me = false;

    if is_pn_user(Some(&from))
        || is_lid_user(Some(&from))
        || is_hosted_lid_user(Some(&from))
        || is_hosted_pn_user(Some(&from))
    {
        if let Some(ref rec) = recipient.filter(|r| !is_jid_meta_ai(Some(r))) {
            if !is_me(&from) && !is_me_lid(&from) {
                return Err(DecodeMessageError::InvalidRecipientNotFromMe);
            }
            from_me = true;
            chat_id = rec.clone();
        } else {
            if is_me(&from) || is_me_lid(&from) {
                from_me = true;
            }
            chat_id = from.clone();
        }
        msg_type = MessageType::Chat;
        author = from.clone();
    } else if is_jid_group(Some(&from)) {
        let Some(ref part) = participant else {
            return Err(DecodeMessageError::MissingParticipant);
        };
        if is_me(part) || is_me_lid(part) {
            from_me = true;
        }
        msg_type = MessageType::Group;
        author = part.clone();
        chat_id = from.clone();
    } else if is_jid_broadcast(Some(&from)) {
        let Some(ref part) = participant else {
            return Err(DecodeMessageError::MissingParticipant);
        };
        let is_participant_me = is_me(part);
        msg_type = if is_jid_status_broadcast(&from) {
            if is_participant_me {
                MessageType::DirectPeerStatus
            } else {
                MessageType::OtherStatus
            }
        } else if is_participant_me {
            MessageType::PeerBroadcast
        } else {
            MessageType::OtherBroadcast
        };
        from_me = is_participant_me;
        chat_id = from.clone();
        author = part.clone();
    } else if is_jid_newsletter(Some(&from)) {
        msg_type = MessageType::Newsletter;
        chat_id = from.clone();
        author = from.clone();
        if is_me(&from) || is_me_lid(&from) {
            from_me = true;
        }
    } else {
        return Err(DecodeMessageError::UnknownMessageType(from));
    }

    let is_group_chat = is_jid_group(Some(&chat_id));
    let key = WaMessageKey {
        remote_jid: Some(chat_id.clone()),
        remote_jid_alt: if !is_group_chat {
            addressing_context.sender_alt.clone()
        } else {
            None
        },
        remote_jid_username: if !is_group_chat {
            stanza
                .attrs
                .get("peer_recipient_username")
                .or_else(|| stanza.attrs.get("recipient_username"))
                .cloned()
        } else {
            None
        },
        from_me: Some(from_me),
        id: Some(msg_id),
        participant: participant.clone(),
        participant_alt: if is_group_chat {
            addressing_context.sender_alt
        } else {
            None
        },
        participant_username: if participant.is_some() {
            stanza.attrs.get("participant_username").cloned()
        } else {
            None
        },
        addressing_mode: Some(addressing_context.addressing_mode),
        server_id: if msg_type == MessageType::Newsletter {
            stanza.attrs.get("server_id").cloned()
        } else {
            None
        },
        is_view_once: None,
    };

    let status = if from_me {
        Some(web_message_info::Status::ServerAck as i32)
    } else {
        None
    };

    let full_message = WaMessage {
        key,
        category: stanza.attrs.get("category").cloned(),
        message_timestamp: stanza.attrs.get("t").and_then(|t| t.parse::<u64>().ok()),
        push_name: stanza.attrs.get("notify").cloned(),
        broadcast: Some(is_jid_broadcast(Some(&from))),
        status,
        ..Default::default()
    };

    let sender = if msg_type == MessageType::Chat {
        author.clone()
    } else {
        chat_id
    };

    Ok(DecodedMessageNode {
        full_message,
        author,
        sender,
        category: stanza.attrs.get("category").cloned(),
    })
}

async fn decrypt_content_child(
    tag: &str,
    enc_type: Option<&str>,
    content: &[u8],
    sender: &str,
    author: &str,
    decryption_jid: &str,
    repository: &LibSignalRepository,
) -> Result<Message, String> {
    let e2e_type = if tag == "plaintext" {
        "plaintext"
    } else {
        enc_type.unwrap_or("")
    };

    let msg_buffer = match e2e_type {
        "skmsg" => repository
            .decrypt_group_message(sender, author, content)
            .await
            .map_err(|e| e.to_string())?,
        "pkmsg" => repository
            .decrypt_message(decryption_jid, MessageCipherType::Pkmsg, content)
            .await
            .map_err(|e| e.to_string())?,
        "msg" => repository
            .decrypt_message(decryption_jid, MessageCipherType::Msg, content)
            .await
            .map_err(|e| e.to_string())?,
        "plaintext" => content.to_vec(),
        other => return Err(format!("Unknown e2e type: {}", other)),
    };

    let proto_slice = if e2e_type != "plaintext" {
        unpad_random_max_16(&msg_buffer).map_err(|e| e.to_string())?
    } else {
        msg_buffer.as_slice()
    };

    let mut msg = Message::decode(proto_slice).map_err(|e| e.to_string())?;
    if let Some(dsm) = msg.device_sent_message.as_ref() {
        if let Some(inner) = dsm.message.as_ref() {
            let inner_ref: &Message = Borrow::borrow(inner);
            msg = inner_ref.clone();
        }
    }

    if let Some(skdm) = msg.sender_key_distribution_message.as_ref() {
        if let (Some(group_id), Some(axolotl_skdm)) = (
            skdm.group_id.as_deref(),
            skdm.axolotl_sender_key_distribution_message.as_deref(),
        ) {
            let _ = repository
                .process_sender_key_distribution_message(group_id, author, axolotl_skdm)
                .await;
        }
    }

    Ok(msg)
}

pub async fn decrypt_message_node(
    stanza: &BinaryNode,
    me_id: &str,
    me_lid: &str,
    repository: &LibSignalRepository,
) -> Result<DecodedMessageNode, DecodeMessageError> {
    let mut decoded = decode_message_node(stanza, me_id, me_lid)?;
    let mut decryptables = 0usize;

    if let Some(BinaryNodeData::List(children)) = &stanza.content {
        for child in children {
            let tag = child.tag.as_str();
            let attrs = &child.attrs;

            if tag == "verified_name" {
                if let Some(BinaryNodeData::Bytes(bytes)) = &child.content {
                    if let Ok(cert) = VerifiedNameCertificate::decode(bytes.as_slice()) {
                        if let Some(details_bytes) = cert.details {
                            if let Ok(details) =
                                verified_name_certificate::Details::decode(details_bytes.as_slice())
                            {
                                decoded.full_message.verified_biz_name = details.verified_name;
                            }
                        }
                    }
                }
            }

            if tag == "unavailable" && attrs.get("type").map(|s| s.as_str()) == Some("view_once") {
                decoded.full_message.key.is_view_once = Some(true);
            }

            if tag == "enc" {
                if let Some(count) = attrs.get("count").and_then(|c| c.parse::<u32>().ok()) {
                    decoded.full_message.retry_count = Some(count);
                }
            }

            if tag != "enc" && tag != "plaintext" {
                continue;
            }

            let Some(BinaryNodeData::Bytes(content)) = &child.content else {
                continue;
            };

            decryptables += 1;

            let decryption_jid = get_decryption_jid(&decoded.author, repository).await;
            if tag != "plaintext" {
                store_mapping_from_envelope(stanza, &decoded.author, repository, &decryption_jid)
                    .await;
            }

            match decrypt_content_child(
                tag,
                attrs.get("type").map(|s| s.as_str()),
                content,
                &decoded.sender,
                &decoded.author,
                &decryption_jid,
                repository,
            )
            .await
            {
                Ok(msg) => {
                    if let Some(existing) = &mut decoded.full_message.message {
                        let encoded = msg.encode_to_vec();
                        if let Err(err) = existing.merge(encoded.as_slice()) {
                            decoded.full_message.message_stub_type =
                                Some(web_message_info::StubType::Ciphertext as i32);
                            decoded.full_message.message_stub_parameters = vec![err.to_string()];
                        }
                    } else {
                        decoded.full_message.message = Some(msg);
                    }
                }
                Err(err_msg) => {
                    decoded.full_message.message_stub_type =
                        Some(web_message_info::StubType::Ciphertext as i32);
                    decoded.full_message.message_stub_parameters = vec![err_msg];
                }
            }
        }
    }

    if decryptables == 0 && decoded.full_message.key.is_view_once != Some(true) {
        decoded.full_message.message_stub_type =
            Some(web_message_info::StubType::Ciphertext as i32);
        decoded.full_message.message_stub_parameters =
            vec![NO_MESSAGE_FOUND_ERROR_TEXT.to_string()];
    }

    Ok(decoded)
}

pub fn is_session_record_error(error_message: &str) -> bool {
    SESSION_RECORD_ERROR_PATTERNS
        .iter()
        .any(|pattern| error_message.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::SenderKeyDistributionMessage as ProtoSkdm;
    use crate::types::{E2ESession, E2ESessionPreKey, E2ESessionSignedPreKey};
    use crate::utils::crypto::{generate_signal_pub_key, Curve};
    use crate::utils::generics::pad_random_max_16;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use crate::wa_binary::BinaryNodeAttributes;
    use rand::Rng;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_decode_message_node_variants() {
        let me_id = "573001111111:1@s.whatsapp.net";
        let me_lid = "111111@lid";

        let group_stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("id".to_string(), "MSG1".to_string()),
                ("from".to_string(), "1203630001@g.us".to_string()),
                ("participant".to_string(), "573002222222@s.whatsapp.net".to_string()),
                ("participant_lid".to_string(), "222222@lid".to_string()),
                ("t".to_string(), "1700000000".to_string()),
                ("notify".to_string(), "Bob".to_string()),
            ]),
            content: None,
        };

        let decoded = decode_message_node(&group_stanza, me_id, me_lid).unwrap();
        assert_eq!(
            decoded.full_message.key.remote_jid.as_deref(),
            Some("1203630001@g.us")
        );
        assert_eq!(
            decoded.full_message.key.participant_alt.as_deref(),
            Some("222222@lid")
        );
        assert_eq!(decoded.full_message.key.from_me, Some(false));
        assert_eq!(decoded.full_message.push_name.as_deref(), Some("Bob"));
    }

    #[tokio::test]
    async fn test_decrypt_message_node_direct_and_group() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir_a = std::env::temp_dir().join(format!("baileys_rs_dec_a_{}", suffix));
        let dir_b = std::env::temp_dir().join(format!("baileys_rs_dec_b_{}", suffix));

        let auth_a = Arc::new(use_multi_file_auth_state(&dir_a).await.unwrap());
        let auth_b = Arc::new(use_multi_file_auth_state(&dir_b).await.unwrap());

        let bob_pre_key = Curve::generate_key_pair();
        let mut pk_map = HashMap::new();
        pk_map.insert(
            "1".to_string(),
            Some(serde_json::to_value(&bob_pre_key).unwrap()),
        );
        let mut pk_batch = HashMap::new();
        pk_batch.insert("pre-key".to_string(), pk_map);
        auth_b.set_keys(pk_batch).await.unwrap();

        let repo_a = LibSignalRepository::new(Arc::clone(&auth_a), None);
        let repo_b = LibSignalRepository::new(Arc::clone(&auth_b), None);

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
                public_key: generate_signal_pub_key(&bob_pre_key.public),
            }),
        };

        let alice_jid = "573001111111@s.whatsapp.net";
        let bob_jid = "573002222222@s.whatsapp.net";
        let group_jid = "120363000999@g.us";

        repo_a.inject_e2e_session(bob_jid, &bob_bundle).await.unwrap();

        let group_plain = Message {
            conversation: Some("hola grupo desde rust".to_string()),
            ..Default::default()
        };
        let enc_group = repo_a
            .encrypt_group_message(group_jid, alice_jid, &pad_random_max_16(&group_plain.encode_to_vec()))
            .await
            .unwrap();

        let direct_proto = Message {
            conversation: Some("hola directo".to_string()),
            sender_key_distribution_message: Some(ProtoSkdm {
                group_id: Some(group_jid.to_string()),
                axolotl_sender_key_distribution_message: Some(enc_group.sender_key_distribution_message),
            }),
            ..Default::default()
        };
        let enc_direct = repo_a
            .encrypt_message(bob_jid, &pad_random_max_16(&direct_proto.encode_to_vec()))
            .await
            .unwrap();

        let direct_stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("id".to_string(), "DIRECT1".to_string()),
                ("from".to_string(), alice_jid.to_string()),
                ("t".to_string(), "1700000001".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "enc".to_string(),
                attrs: BinaryNodeAttributes::from([(
                    "type".to_string(),
                    enc_direct.cipher_type.as_str().to_string(),
                )]),
                content: Some(BinaryNodeData::Bytes(enc_direct.ciphertext)),
            }])),
        };

        let dec_direct = decrypt_message_node(&direct_stanza, bob_jid, "", &repo_b)
            .await
            .unwrap();
        assert_eq!(
            dec_direct
                .full_message
                .message
                .as_ref()
                .and_then(|m| m.conversation.as_deref()),
            Some("hola directo")
        );

        let group_stanza = BinaryNode {
            tag: "message".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("id".to_string(), "GRP1".to_string()),
                ("from".to_string(), group_jid.to_string()),
                ("participant".to_string(), alice_jid.to_string()),
                ("t".to_string(), "1700000002".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "enc".to_string(),
                attrs: BinaryNodeAttributes::from([("type".to_string(), "skmsg".to_string())]),
                content: Some(BinaryNodeData::Bytes(enc_group.ciphertext)),
            }])),
        };

        let dec_group = decrypt_message_node(&group_stanza, bob_jid, "", &repo_b)
            .await
            .unwrap();
        assert_eq!(
            dec_group
                .full_message
                .message
                .as_ref()
                .and_then(|m| m.conversation.as_deref()),
            Some("hola grupo desde rust")
        );

        let _ = tokio::fs::remove_dir_all(&dir_a).await;
        let _ = tokio::fs::remove_dir_all(&dir_b).await;
    }
}
