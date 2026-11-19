use crate::types::AuthenticationCreds;
use crate::utils::make_mutex::KeyedMutex;
use crate::utils::pre_key_manager::{PreKeyManager, SignalDataSet};
use crate::utils::use_multi_file_auth_state::{AuthStateError, MultiFileAuthState};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_SIGNAL_STORE_TTL_SECS: u64 = 5 * 60;

#[derive(Debug, Error)]
pub enum AuthUtilsError {
    #[error("cannot proceed: socket is not authenticated yet (creds.me.id is missing)")]
    NotAuthenticated,
    #[error("auth state error: {0}")]
    AuthState(#[from] AuthStateError),
}

pub fn assert_me_id(creds: &AuthenticationCreds) -> Result<&str, AuthUtilsError> {
    creds
        .me
        .as_ref()
        .map(|m| m.id.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(AuthUtilsError::NotAuthenticated)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionCapabilityOptions {
    pub max_commit_retries: u32,
    pub delay_between_tries_ms: u64,
}

impl Default for TransactionCapabilityOptions {
    fn default() -> Self {
        Self {
            max_commit_retries: 10,
            delay_between_tries_ms: 250,
        }
    }
}

struct CachedSignalEntry {
    value: Option<Value>,
    updated_at: Instant,
}

pub struct CacheableSignalKeyStore {
    store: Arc<MultiFileAuthState>,
    ttl: Duration,
    cache: AsyncMutex<HashMap<String, CachedSignalEntry>>,
}

impl CacheableSignalKeyStore {
    pub fn new(store: Arc<MultiFileAuthState>, ttl_secs: Option<u64>) -> Self {
        Self {
            store,
            ttl: Duration::from_secs(ttl_secs.unwrap_or(DEFAULT_SIGNAL_STORE_TTL_SECS)),
            cache: AsyncMutex::new(HashMap::new()),
        }
    }

    fn unique_id(key_type: &str, id: &str) -> String {
        format!("{}.{}", key_type, id)
    }

    pub async fn get(&self, key_type: &str, ids: &[String]) -> HashMap<String, Option<Value>> {
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| entry.updated_at.elapsed() < self.ttl);

        let mut data = HashMap::new();
        let mut ids_to_fetch = Vec::new();

        for id in ids {
            let uid = Self::unique_id(key_type, id);
            if let Some(entry) = cache.get(&uid) {
                if let Some(ref val) = entry.value {
                    data.insert(id.clone(), Some(val.clone()));
                }
            } else {
                ids_to_fetch.push(id.clone());
            }
        }

        if !ids_to_fetch.is_empty() {
            let fetched = self.store.get_keys(key_type, &ids_to_fetch).await;
            let now = Instant::now();
            for id in ids_to_fetch {
                if let Some(Some(val)) = fetched.get(&id) {
                    data.insert(id.clone(), Some(val.clone()));
                    cache.insert(
                        Self::unique_id(key_type, &id),
                        CachedSignalEntry {
                            value: Some(val.clone()),
                            updated_at: now,
                        },
                    );
                }
            }
        }

        data
    }

    pub async fn set(&self, data: SignalDataSet) -> Result<(), AuthStateError> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        for (key_type, entries) in &data {
            for (id, val) in entries {
                let uid = Self::unique_id(key_type, id);
                match val {
                    Some(v) => {
                        cache.insert(
                            uid,
                            CachedSignalEntry {
                                value: Some(v.clone()),
                                updated_at: now,
                            },
                        );
                    }
                    None => {
                        cache.remove(&uid);
                    }
                }
            }
        }
        self.store.set_keys(data).await
    }

    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }
}

#[derive(Default)]
struct TransactionContext {
    cache: SignalDataSet,
    mutations: SignalDataSet,
    db_queries: usize,
}

tokio::task_local! {
    static TX_STORAGE: Arc<AsyncMutex<TransactionContext>>;
}

pub struct TransactionSignalKeyStore {
    store: Arc<MultiFileAuthState>,
    options: TransactionCapabilityOptions,
    key_queues: KeyedMutex,
    tx_mutexes: KeyedMutex,
    pre_key_manager: PreKeyManager,
}

impl TransactionSignalKeyStore {
    pub fn new(store: Arc<MultiFileAuthState>, options: TransactionCapabilityOptions) -> Self {
        let pre_key_manager = PreKeyManager::new(Arc::clone(&store));
        Self {
            store,
            options,
            key_queues: KeyedMutex::new(),
            tx_mutexes: KeyedMutex::new(),
            pre_key_manager,
        }
    }

    pub fn is_in_transaction(&self) -> bool {
        TX_STORAGE.try_with(|_| ()).is_ok()
    }

    async fn commit_with_retry(&self, mutations: SignalDataSet) -> Result<(), AuthStateError> {
        if mutations.is_empty() {
            return Ok(());
        }

        let max_retries = self.options.max_commit_retries.max(1);
        for attempt in 0..max_retries {
            match self.store.set_keys(mutations.clone()).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let retries_left = max_retries - attempt - 1;
                    if retries_left == 0 {
                        return Err(err);
                    }
                    tokio::time::sleep(Duration::from_millis(self.options.delay_between_tries_ms))
                        .await;
                }
            }
        }
        Ok(())
    }

    pub async fn get(&self, key_type: &str, ids: &[String]) -> HashMap<String, Option<Value>> {
        let current_ctx = TX_STORAGE.try_with(Arc::clone).ok();
        let Some(ctx_arc) = current_ctx else {
            return self.store.get_keys(key_type, ids).await;
        };

        let missing: Vec<String> = {
            let ctx = ctx_arc.lock().await;
            let cached = ctx.cache.get(key_type);
            ids.iter()
                .filter(|id| cached.is_none_or(|m| !m.contains_key(*id)))
                .cloned()
                .collect()
        };

        if !missing.is_empty() {
            let fetched = self
                .tx_mutexes
                .mutex(key_type, || self.store.get_keys(key_type, &missing))
                .await;

            let mut ctx = ctx_arc.lock().await;
            ctx.db_queries += 1;
            let cache_entry = ctx.cache.entry(key_type.to_string()).or_default();
            for id in missing {
                let val = fetched.get(&id).cloned().unwrap_or(None);
                cache_entry.insert(id, val);
            }
        }

        let ctx = ctx_arc.lock().await;
        let mut result = HashMap::new();
        if let Some(cached) = ctx.cache.get(key_type) {
            for id in ids {
                if let Some(Some(val)) = cached.get(id) {
                    result.insert(id.clone(), Some(val.clone()));
                }
            }
        }
        result
    }

    pub async fn set(&self, mut data: SignalDataSet) -> Result<(), AuthStateError> {
        let current_ctx = TX_STORAGE.try_with(Arc::clone).ok();
        let Some(ctx_arc) = current_ctx else {
            if data.contains_key("pre-key") {
                self.pre_key_manager
                    .validate_deletions(&mut data, "pre-key")
                    .await;
            }

            for (key_type, entries) in data {
                if entries.is_empty() {
                    continue;
                }
                let mut single = HashMap::new();
                single.insert(key_type.clone(), entries);
                self.key_queues
                    .mutex(&key_type, || self.store.set_keys(single))
                    .await?;
            }
            return Ok(());
        };

        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        for (key_type, entries) in data {
            ctx.cache.entry(key_type.clone()).or_default();
            ctx.mutations.entry(key_type.clone()).or_default();

            if key_type == "pre-key" {
                let mut single = HashMap::new();
                single.insert(key_type.clone(), entries);
                self.pre_key_manager
                    .process_operations(&single, "pre-key", &mut ctx.cache, &mut ctx.mutations, true)
                    .await;
            } else {
                let cache_map = ctx.cache.get_mut(&key_type).unwrap();
                let mut_map = ctx.mutations.get_mut(&key_type).unwrap();
                for (id, val) in entries {
                    cache_map.insert(id.clone(), val.clone());
                    mut_map.insert(id, val);
                }
            }
        }

        Ok(())
    }

    pub async fn transaction<F, Fut, T, E>(&self, key: &str, work: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: From<AuthStateError>,
    {
        if self.is_in_transaction() {
            return work().await;
        }

        self.tx_mutexes
            .mutex(key, || async move {
                let ctx = Arc::new(AsyncMutex::new(TransactionContext::default()));
                let result = TX_STORAGE.scope(Arc::clone(&ctx), work()).await?;
                let mutations = {
                    let mut guard = ctx.lock().await;
                    std::mem::take(&mut guard.mutations)
                };
                self.commit_with_retry(mutations).await?;
                Ok(result)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{init_auth_creds, ContactInfo};
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;

    #[test]
    fn test_assert_me_id() {
        let mut creds = init_auth_creds().unwrap();
        assert!(matches!(
            assert_me_id(&creds),
            Err(AuthUtilsError::NotAuthenticated)
        ));
        creds.me = Some(ContactInfo {
            id: "573001111111@s.whatsapp.net".to_string(),
            name: None,
            lid: None,
        });
        assert_eq!(assert_me_id(&creds).unwrap(), "573001111111@s.whatsapp.net");
    }

    #[tokio::test]
    async fn test_cacheable_and_transaction_signal_key_store() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_auth_utils_{}", suffix));
        let auth = Arc::new(use_multi_file_auth_state(&dir).await.unwrap());

        let cached = CacheableSignalKeyStore::new(Arc::clone(&auth), Some(60));
        let mut set_map = HashMap::new();
        let mut entries = HashMap::new();
        entries.insert("k1".to_string(), Some(serde_json::json!({"val": 1})));
        set_map.insert("session".to_string(), entries);
        cached.set(set_map).await.unwrap();

        let got = cached.get("session", &["k1".to_string()]).await;
        assert_eq!(
            got.get("k1").and_then(|v| v.as_ref()),
            Some(&serde_json::json!({"val": 1}))
        );

        let tx_store = Arc::new(TransactionSignalKeyStore::new(
            Arc::clone(&auth),
            TransactionCapabilityOptions::default(),
        ));
        assert!(!tx_store.is_in_transaction());

        let tx_ref = Arc::clone(&tx_store);
        let rollback_res: Result<(), AuthStateError> = tx_store
            .transaction("tx-rollback", || async move {
                assert!(tx_ref.is_in_transaction());
                let mut m = HashMap::new();
                let mut e = HashMap::new();
                e.insert("rolled".to_string(), Some(serde_json::json!("nope")));
                m.insert("session".to_string(), e);
                tx_ref.set(m).await?;
                Err(AuthStateError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "abort",
                )))
            })
            .await;
        assert!(rollback_res.is_err());
        assert!(auth
            .get_keys("session", &["rolled".to_string()])
            .await
            .get("rolled")
            .and_then(|v| v.as_ref())
            .is_none());

        let tx_ref2 = Arc::clone(&tx_store);
        tx_store
            .transaction::<_, _, (), AuthStateError>("tx-commit", || async move {
                let mut m = HashMap::new();
                let mut e = HashMap::new();
                e.insert("committed".to_string(), Some(serde_json::json!("ok")));
                m.insert("session".to_string(), e);
                tx_ref2.set(m).await?;
                let inside = tx_ref2.get("session", &["committed".to_string()]).await;
                assert_eq!(
                    inside.get("committed").and_then(|v| v.as_ref()),
                    Some(&serde_json::json!("ok"))
                );
                Ok(())
            })
            .await
            .unwrap();

        let persisted = auth.get_keys("session", &["committed".to_string()]).await;
        assert_eq!(
            persisted.get("committed").and_then(|v| v.as_ref()),
            Some(&serde_json::json!("ok"))
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
