use crate::defaults::KEY_BUNDLE_TYPE;
use crate::types::{
    AuthenticationCreds, E2ESession, E2ESessionPreKey, E2ESessionSignedPreKey, KeyPair,
    PreKeysCredsUpdate, ProtocolAddress, SignalIdentity, SignedKeyPair, USyncDeviceEntry,
};
use crate::utils::crypto::{generate_signal_pub_key, Curve};
use crate::utils::use_multi_file_auth_state::{AuthStateError, MultiFileAuthState};
use crate::utils::validate_connection::encode_big_endian;
use crate::wa_binary::{
    assert_node_error_free, get_binary_node_child, get_binary_node_child_buffer,
    get_binary_node_child_uint, get_binary_node_children, get_server_from_domain_type, jid_decode,
    BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError, FullJid, WaJidDomains,
    S_WHATSAPP_NET,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalUtilsError {
    #[error("binary node error: {0}")]
    BinaryNode(#[from] BinaryNodeError),
    #[error("auth state error: {0}")]
    AuthState(#[from] AuthStateError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing required field in session node: {0}")]
    MissingSessionField(&'static str),
}

pub struct GeneratedPreKeys {
    pub new_pre_keys: BTreeMap<u32, KeyPair>,
    pub last_pre_key_id: u32,
    pub pre_keys_range: (u32, u32),
}

pub struct NextPreKeysResult {
    pub update: PreKeysCredsUpdate,
    pub pre_keys: BTreeMap<u32, KeyPair>,
}

pub struct NextPreKeysNodeResult {
    pub update: PreKeysCredsUpdate,
    pub node: BinaryNode,
}

pub fn create_signal_identity(wid: &str, account_signature_key: &[u8]) -> SignalIdentity {
    SignalIdentity {
        identifier: ProtocolAddress {
            name: wid.to_string(),
            device_id: 0,
        },
        identifier_key: generate_signal_pub_key(account_signature_key),
    }
}

pub async fn get_pre_keys(
    auth: &MultiFileAuthState,
    min: u32,
    limit: u32,
) -> BTreeMap<u32, KeyPair> {
    let id_list: Vec<String> = (min..limit).map(|id| id.to_string()).collect();
    let raw = auth.get_keys("pre-key", &id_list).await;
    let mut out = BTreeMap::new();
    for (id_str, val_opt) in raw {
        if let (Ok(id), Some(val)) = (id_str.parse::<u32>(), val_opt) {
            if let Ok(pair) = serde_json::from_value::<KeyPair>(val) {
                out.insert(id, pair);
            }
        }
    }
    out
}

pub fn generate_or_get_pre_keys(creds: &AuthenticationCreds, range: u32) -> GeneratedPreKeys {
    let available = i64::from(creds.next_pre_key_id) - i64::from(creds.first_unuploaded_pre_key_id);
    let remaining = i64::from(range) - available;
    let last_pre_key_id = (i64::from(creds.next_pre_key_id) + remaining - 1).max(0) as u32;
    let mut new_pre_keys = BTreeMap::new();

    if remaining > 0 {
        for i in creds.next_pre_key_id..=last_pre_key_id {
            new_pre_keys.insert(i, Curve::generate_key_pair());
        }
    }

    GeneratedPreKeys {
        new_pre_keys,
        last_pre_key_id,
        pre_keys_range: (creds.first_unuploaded_pre_key_id, range),
    }
}

pub fn xmpp_signed_pre_key(key: &SignedKeyPair) -> BinaryNode {
    BinaryNode {
        tag: "skey".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::List(vec![
            BinaryNode {
                tag: "id".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(encode_big_endian(key.key_id, 3))),
            },
            BinaryNode {
                tag: "value".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(key.key_pair.public.clone())),
            },
            BinaryNode {
                tag: "signature".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(key.signature.clone())),
            },
        ])),
    }
}

pub fn xmpp_pre_key(pair: &KeyPair, id: u32) -> BinaryNode {
    BinaryNode {
        tag: "key".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::List(vec![
            BinaryNode {
                tag: "id".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(encode_big_endian(id, 3))),
            },
            BinaryNode {
                tag: "value".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(pair.public.clone())),
            },
        ])),
    }
}

pub fn extract_e2e_session_from_retry_receipt(receipt: &BinaryNode) -> Option<E2ESession> {
    let keys_node = get_binary_node_child(Some(receipt), "keys")?;

    let type_buf = get_binary_node_child_buffer(Some(keys_node), "type")?;
    if type_buf.len() != 1 || type_buf[0] != KEY_BUNDLE_TYPE[0] {
        return None;
    }

    let identity = get_binary_node_child_buffer(Some(keys_node), "identity")?;
    let skey = get_binary_node_child(Some(keys_node), "skey")?;
    if identity.len() != 32 {
        return None;
    }

    let registration_id = get_binary_node_child_uint(receipt, "registration", 4)? as u32;

    let signed_pub_key = get_binary_node_child_buffer(Some(skey), "value")?;
    let signed_sig = get_binary_node_child_buffer(Some(skey), "signature")?;
    let signed_key_id = get_binary_node_child_uint(skey, "id", 3)? as u32;
    if signed_pub_key.len() != 32 {
        return None;
    }

    let pre_key = if let Some(pre_key_node) = get_binary_node_child(Some(keys_node), "key") {
        let pre_key_pub = get_binary_node_child_buffer(Some(pre_key_node), "value")?;
        let pre_key_id = get_binary_node_child_uint(pre_key_node, "id", 3)? as u32;
        if pre_key_pub.len() != 32 {
            return None;
        }
        Some(E2ESessionPreKey {
            key_id: pre_key_id,
            public_key: generate_signal_pub_key(pre_key_pub),
        })
    } else {
        None
    };

    Some(E2ESession {
        registration_id,
        identity_key: generate_signal_pub_key(identity),
        signed_pre_key: E2ESessionSignedPreKey {
            key_id: signed_key_id,
            public_key: generate_signal_pub_key(signed_pub_key),
            signature: signed_sig.to_vec(),
        },
        pre_key,
    })
}

pub fn parse_e2e_sessions(node: &BinaryNode) -> Result<Vec<(String, E2ESession)>, SignalUtilsError> {
    let list_node = get_binary_node_child(Some(node), "list");
    let user_nodes = get_binary_node_children(list_node, "user");

    for user_node in &user_nodes {
        assert_node_error_free(user_node)?;
    }

    let mut sessions = Vec::with_capacity(user_nodes.len());
    for user_node in user_nodes {
        let jid = user_node
            .attrs
            .get("jid")
            .cloned()
            .ok_or(SignalUtilsError::MissingSessionField("jid"))?;
        let signed_key = get_binary_node_child(Some(user_node), "skey")
            .ok_or(SignalUtilsError::MissingSessionField("skey"))?;
        let identity = get_binary_node_child_buffer(Some(user_node), "identity")
            .ok_or(SignalUtilsError::MissingSessionField("identity"))?;
        let registration_id = get_binary_node_child_uint(user_node, "registration", 4)
            .ok_or(SignalUtilsError::MissingSessionField("registration"))?
            as u32;

        let signed_key_id = get_binary_node_child_uint(signed_key, "id", 3)
            .ok_or(SignalUtilsError::MissingSessionField("skey.id"))?
            as u32;
        let signed_key_val = get_binary_node_child_buffer(Some(signed_key), "value")
            .ok_or(SignalUtilsError::MissingSessionField("skey.value"))?;
        let signed_key_sig = get_binary_node_child_buffer(Some(signed_key), "signature")
            .ok_or(SignalUtilsError::MissingSessionField("skey.signature"))?;

        let pre_key = if let Some(key_node) = get_binary_node_child(Some(user_node), "key") {
            let key_id = get_binary_node_child_uint(key_node, "id", 3)
                .ok_or(SignalUtilsError::MissingSessionField("key.id"))?
                as u32;
            let key_val = get_binary_node_child_buffer(Some(key_node), "value")
                .ok_or(SignalUtilsError::MissingSessionField("key.value"))?;
            Some(E2ESessionPreKey {
                key_id,
                public_key: generate_signal_pub_key(key_val),
            })
        } else {
            None
        };

        sessions.push((
            jid,
            E2ESession {
                registration_id,
                identity_key: generate_signal_pub_key(identity),
                signed_pre_key: E2ESessionSignedPreKey {
                    key_id: signed_key_id,
                    public_key: generate_signal_pub_key(signed_key_val),
                    signature: signed_key_sig.to_vec(),
                },
                pre_key,
            },
        ));
    }

    Ok(sessions)
}

pub async fn parse_and_inject_e2e_sessions<F, Fut, E>(
    node: &BinaryNode,
    mut inject: F,
) -> Result<(), E>
where
    F: FnMut(String, E2ESession) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: From<SignalUtilsError>,
{
    let sessions = parse_e2e_sessions(node)?;
    for chunk in sessions.chunks(100) {
        for (jid, session) in chunk {
            inject(jid.clone(), session.clone()).await?;
        }
        tokio::task::yield_now().await;
    }
    Ok(())
}

fn domain_from_u32(val: Option<u32>) -> Option<WaJidDomains> {
    match val {
        Some(0) => Some(WaJidDomains::Whatsapp),
        Some(1) => Some(WaJidDomains::Lid),
        Some(128) => Some(WaJidDomains::Hosted),
        Some(129) => Some(WaJidDomains::HostedLid),
        _ => None,
    }
}

pub fn extract_device_jids(
    result: &[USyncDeviceEntry],
    my_jid: &str,
    my_lid: &str,
    exclude_zero_devices: bool,
) -> Vec<FullJid> {
    let Some(my_decoded) = jid_decode(my_jid) else {
        return Vec::new();
    };
    let my_user = my_decoded.user;
    let my_device = my_decoded.device;

    let mut extracted = Vec::new();

    for user_result in result {
        let Some(devices) = &user_result.devices else {
            continue;
        };
        let Some(decoded) = jid_decode(&user_result.id) else {
            continue;
        };

        for dev in &devices.device_list {
            let allow_zero = !exclude_zero_devices || dev.id != 0;
            let not_self_device =
                (my_user != decoded.user && my_lid != decoded.user) || my_device != Some(dev.id);
            let valid_key_index = dev.id == 0 || dev.key_index.is_some_and(|k| k != 0);

            if allow_zero && not_self_device && valid_key_index {
                let domain_type = if dev.is_hosted {
                    if decoded.domain_type == Some(WaJidDomains::Lid as u32) {
                        Some(WaJidDomains::HostedLid as u32)
                    } else {
                        Some(WaJidDomains::Hosted as u32)
                    }
                } else {
                    decoded.domain_type
                };

                let server =
                    get_server_from_domain_type(decoded.server.as_str(), domain_from_u32(domain_type));

                extracted.push(FullJid {
                    user: decoded.user.clone(),
                    device: Some(dev.id),
                    domain_type,
                    server,
                });
            }
        }
    }

    extracted
}

pub async fn get_next_pre_keys(
    auth: &MultiFileAuthState,
    count: u32,
) -> Result<NextPreKeysResult, SignalUtilsError> {
    let generated = generate_or_get_pre_keys(&auth.creds, count);

    let update = PreKeysCredsUpdate {
        next_pre_key_id: generated
            .last_pre_key_id
            .saturating_add(1)
            .max(auth.creds.next_pre_key_id),
        first_unuploaded_pre_key_id: auth
            .creds
            .first_unuploaded_pre_key_id
            .max(generated.last_pre_key_id.saturating_add(1)),
    };

    let mut entries: HashMap<String, Option<Value>> = HashMap::new();
    for (id, pair) in generated.new_pre_keys {
        entries.insert(id.to_string(), Some(serde_json::to_value(pair)?));
    }
    let mut batch = HashMap::new();
    batch.insert("pre-key".to_string(), entries);
    auth.set_keys(batch).await?;

    let (min_id, range) = generated.pre_keys_range;
    let pre_keys = get_pre_keys(auth, min_id, min_id.saturating_add(range)).await;

    Ok(NextPreKeysResult { update, pre_keys })
}

pub async fn get_next_pre_keys_node(
    auth: &MultiFileAuthState,
    count: u32,
) -> Result<NextPreKeysNodeResult, SignalUtilsError> {
    let NextPreKeysResult { update, pre_keys } = get_next_pre_keys(auth, count).await?;

    let key_nodes: Vec<BinaryNode> = pre_keys
        .iter()
        .map(|(&id, pair)| xmpp_pre_key(pair, id))
        .collect();

    let node = BinaryNode {
        tag: "iq".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("xmlns".to_string(), "encrypt".to_string()),
            ("type".to_string(), "set".to_string()),
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
        ]),
        content: Some(BinaryNodeData::List(vec![
            BinaryNode {
                tag: "registration".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(encode_big_endian(
                    auth.creds.registration_id,
                    4,
                ))),
            },
            BinaryNode {
                tag: "type".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(KEY_BUNDLE_TYPE.to_vec())),
            },
            BinaryNode {
                tag: "identity".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(
                    auth.creds.signed_identity_key.public.clone(),
                )),
            },
            BinaryNode {
                tag: "list".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(key_nodes)),
            },
            xmpp_signed_pre_key(&auth.creds.signed_pre_key),
        ])),
    };

    Ok(NextPreKeysNodeResult { update, node })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{init_auth_creds, DeviceListData, ParsedDeviceInfo};
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use crate::wa_binary::JidServer;
    use rand::Rng;

    #[test]
    fn test_generate_and_xmpp_pre_keys() {
        let creds = init_auth_creds().unwrap();
        let gen = generate_or_get_pre_keys(&creds, 5);
        assert_eq!(gen.new_pre_keys.len(), 5);
        assert_eq!(gen.last_pre_key_id, 5);
        assert_eq!(gen.pre_keys_range, (1, 5));

        let skey_node = xmpp_signed_pre_key(&creds.signed_pre_key);
        assert_eq!(skey_node.tag, "skey");
        let pkey_node = xmpp_pre_key(gen.new_pre_keys.get(&1).unwrap(), 1);
        assert_eq!(pkey_node.tag, "key");
    }

    #[test]
    fn test_extract_e2e_session_from_retry_receipt() {
        let receipt = BinaryNode {
            tag: "receipt".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![
                BinaryNode {
                    tag: "registration".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::Bytes(encode_big_endian(4242, 4))),
                },
                BinaryNode {
                    tag: "keys".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![
                        BinaryNode {
                            tag: "type".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::Bytes(vec![5])),
                        },
                        BinaryNode {
                            tag: "identity".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::Bytes(vec![1u8; 32])),
                        },
                        BinaryNode {
                            tag: "skey".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::List(vec![
                                BinaryNode {
                                    tag: "id".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::Bytes(encode_big_endian(7, 3))),
                                },
                                BinaryNode {
                                    tag: "value".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::Bytes(vec![2u8; 32])),
                                },
                                BinaryNode {
                                    tag: "signature".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::Bytes(vec![3u8; 64])),
                                },
                            ])),
                        },
                        BinaryNode {
                            tag: "key".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::List(vec![
                                BinaryNode {
                                    tag: "id".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::Bytes(encode_big_endian(9, 3))),
                                },
                                BinaryNode {
                                    tag: "value".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::Bytes(vec![4u8; 32])),
                                },
                            ])),
                        },
                    ])),
                },
            ])),
        };

        let session = extract_e2e_session_from_retry_receipt(&receipt).unwrap();
        assert_eq!(session.registration_id, 4242);
        assert_eq!(session.identity_key.len(), 33);
        assert_eq!(session.signed_pre_key.key_id, 7);
        assert_eq!(session.pre_key.unwrap().key_id, 9);
    }

    #[test]
    fn test_extract_device_jids() {
        let entries = vec![USyncDeviceEntry {
            id: "573001234567@s.whatsapp.net".to_string(),
            devices: Some(ParsedDeviceInfo {
                device_list: vec![
                    DeviceListData {
                        id: 0,
                        key_index: None,
                        is_hosted: false,
                    },
                    DeviceListData {
                        id: 2,
                        key_index: Some(1),
                        is_hosted: false,
                    },
                    DeviceListData {
                        id: 3,
                        key_index: Some(2),
                        is_hosted: true,
                    },
                ],
            }),
        }];

        let out = extract_device_jids(&entries, "573001234567:2@s.whatsapp.net", "999", false);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].device, Some(0));
        assert_eq!(out[0].server, JidServer::SWhatsappNet);
        assert_eq!(out[1].device, Some(3));
        assert_eq!(out[1].server, JidServer::Hosted);
    }

    #[tokio::test]
    async fn test_get_next_pre_keys_node() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_prekeys_test_{}", suffix));
        let auth = use_multi_file_auth_state(&dir).await.unwrap();

        let res = get_next_pre_keys_node(&auth, 5).await.unwrap();
        assert_eq!(res.update.next_pre_key_id, 6);
        assert_eq!(res.update.first_unuploaded_pre_key_id, 6);
        assert_eq!(res.node.tag, "iq");

        let list_node = get_binary_node_child(Some(&res.node), "list").unwrap();
        let keys = get_binary_node_children(Some(list_node), "key");
        assert_eq!(keys.len(), 5);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
