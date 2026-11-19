use crate::utils::use_multi_file_auth_state::MultiFileAuthState;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

pub type SignalDataSet = HashMap<String, HashMap<String, Option<Value>>>;

pub struct PreKeyManager {
    store: Arc<MultiFileAuthState>,
    queues: AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl PreKeyManager {
    pub fn new(store: Arc<MultiFileAuthState>) -> Self {
        Self {
            store,
            queues: AsyncMutex::new(HashMap::new()),
        }
    }

    async fn get_queue(&self, key_type: &str) -> Arc<AsyncMutex<()>> {
        let mut queues = self.queues.lock().await;
        queues
            .entry(key_type.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    pub async fn process_operations(
        &self,
        data: &SignalDataSet,
        key_type: &str,
        transaction_cache: &mut SignalDataSet,
        mutations: &mut SignalDataSet,
        is_in_transaction: bool,
    ) {
        let Some(key_data) = data.get(key_type) else {
            return;
        };

        let queue = self.get_queue(key_type).await;
        let _guard = queue.lock().await;

        transaction_cache
            .entry(key_type.to_string())
            .or_default();
        mutations.entry(key_type.to_string()).or_default();

        let mut deletions = Vec::new();
        let mut updates = HashMap::new();

        for (key_id, value) in key_data {
            match value {
                None => deletions.push(key_id.clone()),
                Some(v) => {
                    updates.insert(key_id.clone(), Some(v.clone()));
                }
            }
        }

        if !updates.is_empty() {
            let cache_map = transaction_cache.get_mut(key_type).unwrap();
            let mut_map = mutations.get_mut(key_type).unwrap();
            for (k, v) in updates {
                cache_map.insert(k.clone(), v.clone());
                mut_map.insert(k, v);
            }
        }

        if !deletions.is_empty() {
            self.process_deletions(
                key_type,
                &deletions,
                transaction_cache,
                mutations,
                is_in_transaction,
            )
            .await;
        }
    }

    async fn process_deletions(
        &self,
        key_type: &str,
        ids: &[String],
        transaction_cache: &mut SignalDataSet,
        mutations: &mut SignalDataSet,
        is_in_transaction: bool,
    ) {
        if is_in_transaction {
            let cache_map = transaction_cache.entry(key_type.to_string()).or_default();
            let mut_map = mutations.entry(key_type.to_string()).or_default();
            for key_id in ids {
                if cache_map.get(key_id).and_then(|v| v.as_ref()).is_some() {
                    cache_map.insert(key_id.clone(), None);
                    mut_map.insert(key_id.clone(), None);
                }
            }
        } else {
            let existing = self.store.get_keys(key_type, ids).await;
            let cache_map = transaction_cache.entry(key_type.to_string()).or_default();
            let mut_map = mutations.entry(key_type.to_string()).or_default();
            for key_id in ids {
                if existing.get(key_id).and_then(|v| v.as_ref()).is_some() {
                    cache_map.insert(key_id.clone(), None);
                    mut_map.insert(key_id.clone(), None);
                }
            }
        }
    }

    pub async fn validate_deletions(&self, data: &mut SignalDataSet, key_type: &str) {
        let queue = self.get_queue(key_type).await;
        let _guard = queue.lock().await;

        let deletion_ids: Vec<String> = match data.get(key_type) {
            Some(map) => map
                .iter()
                .filter_map(|(id, val)| if val.is_none() { Some(id.clone()) } else { None })
                .collect(),
            None => return,
        };

        if deletion_ids.is_empty() {
            return;
        }

        let existing = self.store.get_keys(key_type, &deletion_ids).await;
        if let Some(map) = data.get_mut(key_type) {
            for key_id in deletion_ids {
                if existing.get(&key_id).and_then(|v| v.as_ref()).is_none() {
                    map.remove(&key_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_pre_key_manager_operations_and_validation() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_pkm_{}", suffix));
        let auth = Arc::new(use_multi_file_auth_state(&dir).await.unwrap());

        let mut init_entries = HashMap::new();
        init_entries.insert("1".to_string(), Some(serde_json::json!({"k": "v1"})));
        let mut init_batch = HashMap::new();
        init_batch.insert("pre-key".to_string(), init_entries);
        auth.set_keys(init_batch).await.unwrap();

        let mgr = PreKeyManager::new(Arc::clone(&auth));

        let mut req = HashMap::new();
        let mut ops = HashMap::new();
        ops.insert("1".to_string(), None);
        ops.insert("999".to_string(), None);
        ops.insert("2".to_string(), Some(serde_json::json!({"k": "v2"})));
        req.insert("pre-key".to_string(), ops);

        let mut tx_cache = HashMap::new();
        let mut mutations = HashMap::new();
        mgr.process_operations(&req, "pre-key", &mut tx_cache, &mut mutations, false)
            .await;

        let mut_pk = mutations.get("pre-key").unwrap();
        assert_eq!(mut_pk.get("1"), Some(&None));
        assert!(!mut_pk.contains_key("999"));
        assert!(mut_pk.get("2").and_then(|v| v.as_ref()).is_some());

        let mut to_validate = HashMap::new();
        let mut del_ops = HashMap::new();
        del_ops.insert("1".to_string(), None);
        del_ops.insert("404".to_string(), None);
        to_validate.insert("pre-key".to_string(), del_ops);
        mgr.validate_deletions(&mut to_validate, "pre-key").await;

        let validated = to_validate.get("pre-key").unwrap();
        assert!(validated.contains_key("1"));
        assert!(!validated.contains_key("404"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
