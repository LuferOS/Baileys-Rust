use crate::signal::LibSignalRepository;
use crate::wa_binary::{are_jids_same_user, get_binary_node_child, jid_decode, BinaryNode};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityChangeResult {
    NoIdentityNode,
    InvalidNotification,
    SkippedCompanionDevice(u32),
    SkippedSelfPrimary,
    Debounced,
    SkippedOffline,
    SkippedNoSession,
    SessionRefreshed,
    SessionRefreshFailed(String),
}

pub struct IdentityDebounceCache {
    ttl: Duration,
    entries: Mutex<HashMap<String, Instant>>,
}

impl Default for IdentityDebounceCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl IdentityDebounceCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_debounced(&self, key: &str) -> bool {
        let mut map = self.entries.lock().unwrap();
        map.retain(|_, ts| ts.elapsed() < self.ttl);
        map.contains_key(key)
    }

    pub fn mark(&self, key: String) {
        let mut map = self.entries.lock().unwrap();
        map.insert(key, Instant::now());
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

pub async fn handle_identity_change<F, Fut, E, B>(
    node: &BinaryNode,
    me_id: Option<&str>,
    me_lid: Option<&str>,
    signal_repository: &LibSignalRepository,
    debounce_cache: &IdentityDebounceCache,
    on_before_session_refresh: Option<B>,
    assert_sessions_fn: F,
) -> IdentityChangeResult
where
    F: FnOnce(Vec<String>, bool) -> Fut,
    Fut: Future<Output = Result<bool, E>>,
    E: ToString,
    B: FnOnce(&str),
{
    let Some(from) = node.attrs.get("from").filter(|s| !s.is_empty()) else {
        return IdentityChangeResult::InvalidNotification;
    };

    if get_binary_node_child(Some(node), "identity").is_none() {
        return IdentityChangeResult::NoIdentityNode;
    }

    if let Some(decoded) = jid_decode(from) {
        if let Some(device) = decoded.device {
            if device != 0 {
                return IdentityChangeResult::SkippedCompanionDevice(device);
            }
        }
    }

    let is_self_primary = me_id.is_some()
        && (are_jids_same_user(Some(from), me_id)
            || (me_lid.is_some() && are_jids_same_user(Some(from), me_lid)));
    if is_self_primary {
        return IdentityChangeResult::SkippedSelfPrimary;
    }

    if debounce_cache.is_debounced(from) {
        return IdentityChangeResult::Debounced;
    }
    debounce_cache.mark(from.clone());

    let is_offline = node.attrs.get("offline").is_some_and(|v| !v.is_empty());
    let has_session = signal_repository.validate_session(from).await;
    if !has_session.exists {
        return IdentityChangeResult::SkippedNoSession;
    }

    if is_offline {
        return IdentityChangeResult::SkippedOffline;
    }

    if let Some(hook) = on_before_session_refresh {
        hook(from);
    }

    match assert_sessions_fn(vec![from.clone()], true).await {
        Ok(_) => IdentityChangeResult::SessionRefreshed,
        Err(err) => IdentityChangeResult::SessionRefreshFailed(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{E2ESession, E2ESessionPreKey, E2ESessionSignedPreKey};
    use crate::utils::crypto::{generate_signal_pub_key, Curve};
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use crate::wa_binary::{BinaryNodeAttributes, BinaryNodeData};
    use rand::Rng;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_handle_identity_change_branches() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir_a = std::env::temp_dir().join(format!("baileys_rs_idch_a_{}", suffix));
        let dir_b = std::env::temp_dir().join(format!("baileys_rs_idch_b_{}", suffix));

        let auth_a = Arc::new(use_multi_file_auth_state(&dir_a).await.unwrap());
        let auth_b = Arc::new(use_multi_file_auth_state(&dir_b).await.unwrap());
        let repo = LibSignalRepository::new(Arc::clone(&auth_a), None);
        let debounce = IdentityDebounceCache::default();

        let no_id_node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([(
                "from".to_string(),
                "573002222222@s.whatsapp.net".to_string(),
            )]),
            content: None,
        };
        let res = handle_identity_change(
            &no_id_node,
            Some("573001111111@s.whatsapp.net"),
            None,
            &repo,
            &debounce,
            None::<fn(&str)>,
            |_, _| async { Ok::<bool, &'static str>(true) },
        )
        .await;
        assert_eq!(res, IdentityChangeResult::NoIdentityNode);

        let companion_node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([(
                "from".to_string(),
                "573002222222:2@s.whatsapp.net".to_string(),
            )]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "identity".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: None,
            }])),
        };
        let res = handle_identity_change(
            &companion_node,
            Some("573001111111@s.whatsapp.net"),
            None,
            &repo,
            &debounce,
            None::<fn(&str)>,
            |_, _| async { Ok::<bool, &'static str>(true) },
        )
        .await;
        assert_eq!(res, IdentityChangeResult::SkippedCompanionDevice(2));

        let bob_jid = "573002222222@s.whatsapp.net";
        let bob_pk = Curve::generate_key_pair();
        repo.inject_e2e_session(
            bob_jid,
            &E2ESession {
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
            },
        )
        .await
        .unwrap();

        let valid_node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([("from".to_string(), bob_jid.to_string())]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "identity".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: None,
            }])),
        };

        let res = handle_identity_change(
            &valid_node,
            Some("573001111111@s.whatsapp.net"),
            None,
            &repo,
            &debounce,
            None::<fn(&str)>,
            |_, _| async { Ok::<bool, &'static str>(true) },
        )
        .await;
        assert_eq!(res, IdentityChangeResult::SessionRefreshed);

        let res_debounced = handle_identity_change(
            &valid_node,
            Some("573001111111@s.whatsapp.net"),
            None,
            &repo,
            &debounce,
            None::<fn(&str)>,
            |_, _| async { Ok::<bool, &'static str>(true) },
        )
        .await;
        assert_eq!(res_debounced, IdentityChangeResult::Debounced);

        let _ = tokio::fs::remove_dir_all(&dir_a).await;
        let _ = tokio::fs::remove_dir_all(&dir_b).await;
    }
}
