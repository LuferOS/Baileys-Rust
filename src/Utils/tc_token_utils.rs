use crate::signal::LidMappingStore;
use crate::utils::generics::unix_timestamp_seconds;
use crate::utils::use_multi_file_auth_state::{AuthStateError, MultiFileAuthState};
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_children, is_hosted_lid_user, is_hosted_pn_user,
    is_jid_meta_ai, is_lid_user, is_pn_user, jid_normalized_user, BinaryNode, BinaryNodeAttributes,
    BinaryNodeData,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const TC_TOKEN_BUCKET_DURATION: u64 = 604_800;
const TC_TOKEN_NUM_BUCKETS: u64 = 4;
pub const TC_TOKEN_INDEX_KEY: &str = "__index";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcTokenEntry {
    #[serde(default)]
    pub token: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(rename = "senderTimestamp", skip_serializing_if = "Option::is_none")]
    pub sender_timestamp: Option<u64>,
}

fn is_bot_phone(user: &str) -> bool {
    if user.len() != 11 || !user.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    user.starts_with("1313555") || user.starts_with("131655500")
}

pub fn is_regular_user(jid: Option<&str>) -> bool {
    let Some(jid) = jid else {
        return false;
    };
    let user = jid.split('@').next().unwrap_or("");
    if user == "0" || is_bot_phone(user) || is_jid_meta_ai(Some(jid)) {
        return false;
    }
    is_pn_user(Some(jid))
        || is_lid_user(Some(jid))
        || is_hosted_pn_user(Some(jid))
        || is_hosted_lid_user(Some(jid))
        || jid.ends_with("@c.us")
}

pub async fn read_tc_token_index(auth: &MultiFileAuthState) -> Vec<String> {
    let data = auth
        .get_keys("tctoken", &[TC_TOKEN_INDEX_KEY.to_string()])
        .await;
    let Some(Some(val)) = data.get(TC_TOKEN_INDEX_KEY) else {
        return Vec::new();
    };
    let Ok(entry) = serde_json::from_value::<TcTokenEntry>(val.clone()) else {
        return Vec::new();
    };
    if entry.token.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_slice::<Vec<String>>(&entry.token) else {
        return Vec::new();
    };
    parsed
        .into_iter()
        .filter(|j| !j.is_empty() && j != TC_TOKEN_INDEX_KEY)
        .collect()
}

pub async fn build_merged_tc_token_index_write(
    auth: &MultiFileAuthState,
    added_jids: &[String],
) -> Result<HashMap<String, Option<Value>>, serde_json::Error> {
    let persisted = read_tc_token_index(auth).await;
    let mut merged: HashSet<String> = persisted.into_iter().collect();
    for jid in added_jids {
        if !jid.is_empty() && jid != TC_TOKEN_INDEX_KEY {
            merged.insert(jid.clone());
        }
    }
    let list: Vec<String> = merged.into_iter().collect();
    let entry = TcTokenEntry {
        token: serde_json::to_vec(&list)?,
        timestamp: None,
        sender_timestamp: None,
    };
    let mut out = HashMap::new();
    out.insert(
        TC_TOKEN_INDEX_KEY.to_string(),
        Some(serde_json::to_value(entry)?),
    );
    Ok(out)
}

pub fn is_tc_token_expired(timestamp: Option<u64>) -> bool {
    let Some(ts) = timestamp else {
        return true;
    };
    let now = unix_timestamp_seconds();
    let current_bucket = now / TC_TOKEN_BUCKET_DURATION;
    let cutoff_bucket = current_bucket.saturating_sub(TC_TOKEN_NUM_BUCKETS - 1);
    let cutoff_timestamp = cutoff_bucket.saturating_mul(TC_TOKEN_BUCKET_DURATION);
    ts < cutoff_timestamp
}

pub fn is_tc_token_expired_str(timestamp: Option<&str>) -> bool {
    let parsed = timestamp.and_then(|s| s.parse::<u64>().ok());
    is_tc_token_expired(parsed)
}

pub fn should_send_new_tc_token(sender_timestamp: Option<u64>) -> bool {
    let Some(ts) = sender_timestamp else {
        return true;
    };
    let now = unix_timestamp_seconds();
    let current_bucket = now / TC_TOKEN_BUCKET_DURATION;
    let sender_bucket = ts / TC_TOKEN_BUCKET_DURATION;
    current_bucket > sender_bucket
}

pub async fn resolve_tc_token_jid(jid: &str, lid_mapping: &LidMappingStore) -> String {
    if is_lid_user(Some(jid)) {
        return jid.to_string();
    }
    lid_mapping
        .get_lid_for_pn(jid)
        .await
        .unwrap_or_else(|| jid.to_string())
}

pub async fn resolve_issuance_jid(
    jid: &str,
    issue_to_lid: bool,
    lid_mapping: &LidMappingStore,
) -> String {
    if issue_to_lid {
        if is_lid_user(Some(jid)) {
            return jid.to_string();
        }
        return lid_mapping
            .get_lid_for_pn(jid)
            .await
            .unwrap_or_else(|| jid.to_string());
    }

    if !is_lid_user(Some(jid)) {
        return jid.to_string();
    }
    lid_mapping
        .get_pn_for_lid(jid)
        .await
        .unwrap_or_else(|| jid.to_string())
}

pub async fn build_tc_token_from_jid(
    auth: &MultiFileAuthState,
    jid: &str,
    mut base_content: Vec<BinaryNode>,
    lid_mapping: &LidMappingStore,
) -> Option<Vec<BinaryNode>> {
    let storage_jid = resolve_tc_token_jid(jid, lid_mapping).await;
    let data = auth.get_keys("tctoken", &[storage_jid.clone()]).await;
    let entry = data
        .get(&storage_jid)
        .and_then(|v| v.as_ref())
        .and_then(|v| serde_json::from_value::<TcTokenEntry>(v.clone()).ok());

    let Some(entry) = entry else {
        return if base_content.is_empty() {
            None
        } else {
            Some(base_content)
        };
    };

    if entry.token.is_empty()
        || entry.timestamp.is_none()
        || is_tc_token_expired_str(entry.timestamp.as_deref())
    {
        if !entry.token.is_empty() {
            let cleared = entry.sender_timestamp.and_then(|st| {
                serde_json::to_value(TcTokenEntry {
                    token: Vec::new(),
                    timestamp: None,
                    sender_timestamp: Some(st),
                })
                .ok()
            });
            let mut entries = HashMap::new();
            entries.insert(storage_jid, cleared);
            let mut batch = HashMap::new();
            batch.insert("tctoken".to_string(), entries);
            let _ = auth.set_keys(batch).await;
        }
        return if base_content.is_empty() {
            None
        } else {
            Some(base_content)
        };
    }

    let ts = entry.timestamp.unwrap_or_default();
    base_content.push(BinaryNode {
        tag: "tctoken".to_string(),
        attrs: BinaryNodeAttributes::from([("t".to_string(), ts)]),
        content: Some(BinaryNodeData::Bytes(entry.token)),
    });

    Some(base_content)
}

pub async fn store_tc_tokens_from_iq_result(
    result: &BinaryNode,
    fallback_jid: &str,
    auth: &MultiFileAuthState,
    lid_mapping: &LidMappingStore,
) -> Result<Vec<String>, AuthStateError> {
    let Some(tokens_node) = get_binary_node_child(Some(result), "tokens") else {
        return Ok(Vec::new());
    };

    let mut stored_jids = Vec::new();
    for token_node in get_binary_node_children(Some(tokens_node), "token") {
        if token_node.attrs.get("type").map(|s| s.as_str()) != Some("trusted_contact") {
            continue;
        }
        let Some(BinaryNodeData::Bytes(token_bytes)) = &token_node.content else {
            continue;
        };

        let raw_source = if !fallback_jid.is_empty() {
            Some(fallback_jid)
        } else {
            token_node.attrs.get("jid").map(|s| s.as_str())
        };
        let raw_jid = jid_normalized_user(raw_source);
        if !is_regular_user(Some(&raw_jid)) {
            continue;
        }

        let storage_jid = resolve_tc_token_jid(&raw_jid, lid_mapping).await;
        let existing_data = auth.get_keys("tctoken", &[storage_jid.clone()]).await;
        let existing_entry = existing_data
            .get(&storage_jid)
            .and_then(|v| v.as_ref())
            .and_then(|v| serde_json::from_value::<TcTokenEntry>(v.clone()).ok());

        let existing_ts = existing_entry
            .as_ref()
            .and_then(|e| e.timestamp.as_deref())
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0);
        let incoming_ts = token_node
            .attrs
            .get("t")
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0);

        if incoming_ts == 0 || (existing_ts > 0 && existing_ts > incoming_ts) {
            continue;
        }

        let updated = TcTokenEntry {
            token: token_bytes.clone(),
            timestamp: token_node.attrs.get("t").cloned(),
            sender_timestamp: existing_entry.and_then(|e| e.sender_timestamp),
        };

        let mut entries = HashMap::new();
        entries.insert(storage_jid.clone(), Some(serde_json::to_value(updated)?));
        let mut batch = HashMap::new();
        batch.insert("tctoken".to_string(), entries);
        auth.set_keys(batch).await?;
        stored_jids.push(storage_jid);
    }

    Ok(stored_jids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;
    use std::sync::Arc;

    #[test]
    fn test_regular_user_and_expiry() {
        assert!(is_regular_user(Some("573001234567@s.whatsapp.net")));
        assert!(is_regular_user(Some("987654321@lid")));
        assert!(!is_regular_user(Some("0@s.whatsapp.net")));
        assert!(!is_regular_user(Some("13135550002@s.whatsapp.net")));
        assert!(!is_regular_user(Some("1203630001@g.us")));

        let now = unix_timestamp_seconds();
        assert!(!is_tc_token_expired(Some(now)));
        assert!(is_tc_token_expired(Some(1000)));
        assert!(is_tc_token_expired(None));
        assert!(!should_send_new_tc_token(Some(now)));
        assert!(should_send_new_tc_token(Some(now.saturating_sub(700_000))));
    }

    #[tokio::test]
    async fn test_store_build_and_index_tc_token() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_tctoken_{}", suffix));
        let auth = Arc::new(use_multi_file_auth_state(&dir).await.unwrap());
        let lid_store = LidMappingStore::new(Arc::clone(&auth), None);

        let now = unix_timestamp_seconds().to_string();
        let iq = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "tokens".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "token".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("type".to_string(), "trusted_contact".to_string()),
                        ("t".to_string(), now.clone()),
                    ]),
                    content: Some(BinaryNodeData::Bytes(vec![10, 20, 30])),
                }])),
            }])),
        };

        let target = "573001234567@s.whatsapp.net";
        let stored = store_tc_tokens_from_iq_result(&iq, target, &auth, &lid_store)
            .await
            .unwrap();
        assert_eq!(stored, vec![target.to_string()]);

        let nodes = build_tc_token_from_jid(&auth, target, Vec::new(), &lid_store)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].tag, "tctoken");
        assert_eq!(nodes[0].attrs.get("t").map(|s| s.as_str()), Some(now.as_str()));

        let write = build_merged_tc_token_index_write(&auth, &stored)
            .await
            .unwrap();
        let mut batch = HashMap::new();
        batch.insert("tctoken".to_string(), write);
        auth.set_keys(batch).await.unwrap();

        let idx = read_tc_token_index(&auth).await;
        assert_eq!(idx, vec![target.to_string()]);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
