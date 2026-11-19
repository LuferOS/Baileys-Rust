use crate::types::{init_auth_creds, AuthenticationCreds};
use crate::utils::crypto::CryptoError;
use futures_util::future::join_all;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::{Mutex, RwLock};

const MAX_KEY_CACHE_ENTRIES: usize = 1024;
const FILE_LOCK_SHARDS: usize = 64;

#[derive(Debug, Error)]
pub enum AuthStateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("path {0} exists and is not a directory")]
    NotADirectory(String),
}

struct KeyCache {
    entries: HashMap<String, Option<Value>>,
    order: VecDeque<String>,
}

impl KeyCache {
    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(256),
            order: VecDeque::with_capacity(256),
        }
    }

    fn get(&self, key: &str) -> Option<&Option<Value>> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: String, value: Option<Value>) {
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= MAX_KEY_CACHE_ENTRIES {
                if let Some(oldest) = self.order.pop_front() {
                    self.entries.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value);
    }
}

pub struct MultiFileAuthState {
    folder: PathBuf,
    pub creds: AuthenticationCreds,
    shards: Arc<Vec<Mutex<()>>>,
    cache: Arc<RwLock<KeyCache>>,
}

fn fix_file_name(file: &str) -> String {
    file.replace('/', "__").replace(':', "-")
}

fn shard_index(key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % FILE_LOCK_SHARDS
}

impl MultiFileAuthState {
    pub async fn new(folder: impl AsRef<Path>) -> Result<Self, AuthStateError> {
        let folder = folder.as_ref().to_path_buf();

        match fs::metadata(&folder).await {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(AuthStateError::NotADirectory(
                        folder.to_string_lossy().into_owned(),
                    ));
                }
            }
            Err(_) => {
                fs::create_dir_all(&folder).await?;
            }
        }

        let mut shards = Vec::with_capacity(FILE_LOCK_SHARDS);
        for _ in 0..FILE_LOCK_SHARDS {
            shards.push(Mutex::new(()));
        }

        let mut state = Self {
            folder,
            creds: init_auth_creds()?,
            shards: Arc::new(shards),
            cache: Arc::new(RwLock::new(KeyCache::new())),
        };

        if let Some(loaded) = state.read_data::<AuthenticationCreds>("creds.json").await {
            state.creds = loaded;
        }

        Ok(state)
    }

    async fn write_data<T: Serialize>(&self, data: &T, file: &str) -> Result<(), AuthStateError> {
        let fixed = fix_file_name(file);
        let file_path = self.folder.join(&fixed);
        let tmp_path = self.folder.join(format!("{}.tmp", fixed));
        let serialized = serde_json::to_vec(data)?;
        let _guard = self.shards[shard_index(&fixed)].lock().await;
        fs::write(&tmp_path, serialized).await?;
        fs::rename(&tmp_path, &file_path).await?;
        Ok(())
    }

    async fn read_data<T: DeserializeOwned>(&self, file: &str) -> Option<T> {
        let fixed = fix_file_name(file);
        let file_path = self.folder.join(&fixed);
        let _guard = self.shards[shard_index(&fixed)].lock().await;
        let raw = fs::read(&file_path).await.ok()?;
        serde_json::from_slice(&raw).ok()
    }

    async fn remove_data(&self, file: &str) {
        let fixed = fix_file_name(file);
        let file_path = self.folder.join(&fixed);
        let _guard = self.shards[shard_index(&fixed)].lock().await;
        let _ = fs::remove_file(&file_path).await;
    }

    pub async fn save_creds(&self) -> Result<(), AuthStateError> {
        self.write_data(&self.creds, "creds.json").await
    }

    pub async fn write_creds(&self, creds: &AuthenticationCreds) -> Result<(), AuthStateError> {
        self.write_data(creds, "creds.json").await
    }

    pub async fn get_keys(&self, key_type: &str, ids: &[String]) -> HashMap<String, Option<Value>> {
        let mut result = HashMap::with_capacity(ids.len());
        let mut misses: Vec<(String, String)> = Vec::new();

        {
            let guard = self.cache.read().await;
            for id in ids {
                let file = format!("{}-{}.json", key_type, id);
                if let Some(cached) = guard.get(&file) {
                    result.insert(id.clone(), cached.clone());
                } else {
                    misses.push((id.clone(), file));
                }
            }
        }

        if misses.is_empty() {
            return result;
        }

        let fetches = misses.into_iter().map(|(id, file)| async move {
            let value = self.read_data::<Value>(&file).await;
            (id, file, value)
        });
        let loaded = join_all(fetches).await;

        let mut guard = self.cache.write().await;
        for (id, file, value) in loaded {
            guard.insert(file, value.clone());
            result.insert(id, value);
        }

        result
    }

    pub async fn set_keys(
        &self,
        data: HashMap<String, HashMap<String, Option<Value>>>,
    ) -> Result<(), AuthStateError> {
        let mut ops: Vec<(String, Option<Value>)> = Vec::new();

        {
            let mut guard = self.cache.write().await;
            for (category, entries) in data {
                for (id, value) in entries {
                    let file = format!("{}-{}.json", category, id);
                    guard.insert(file.clone(), value.clone());
                    ops.push((file, value));
                }
            }
        }

        let tasks = ops.into_iter().map(|(file, value)| async move {
            match value {
                Some(v) => self.write_data(&v, &file).await,
                None => {
                    self.remove_data(&file).await;
                    Ok(())
                }
            }
        });

        for res in join_all(tasks).await {
            res?;
        }

        Ok(())
    }

    pub async fn clear_cache(&self) {
        let mut guard = self.cache.write().await;
        guard.entries.clear();
        guard.order.clear();
    }
}

pub async fn use_multi_file_auth_state(
    folder: impl AsRef<Path>,
) -> Result<MultiFileAuthState, AuthStateError> {
    MultiFileAuthState::new(folder).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[tokio::test]
    async fn test_multi_file_auth_state_roundtrip() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_auth_test_{}", suffix));

        let mut auth = use_multi_file_auth_state(&dir).await.unwrap();
        let original_reg_id = auth.creds.registration_id;
        auth.creds.registered = true;
        auth.save_creds().await.unwrap();

        let mut entries = HashMap::new();
        entries.insert(
            "573001234567:1".to_string(),
            Some(serde_json::json!({"ok": true})),
        );
        let mut batch = HashMap::new();
        batch.insert("session".to_string(), entries);
        auth.set_keys(batch).await.unwrap();

        let reloaded = use_multi_file_auth_state(&dir).await.unwrap();
        assert_eq!(reloaded.creds.registration_id, original_reg_id);
        assert!(reloaded.creds.registered);

        let keys = reloaded
            .get_keys("session", &["573001234567:1".to_string()])
            .await;
        assert_eq!(
            keys.get("573001234567:1").unwrap(),
            &Some(serde_json::json!({"ok": true}))
        );

        let mut remove_entries = HashMap::new();
        remove_entries.insert("573001234567:1".to_string(), None);
        let mut remove_batch = HashMap::new();
        remove_batch.insert("session".to_string(), remove_entries);
        reloaded.set_keys(remove_batch).await.unwrap();

        let after_remove = reloaded
            .get_keys("session", &["573001234567:1".to_string()])
            .await;
        assert_eq!(after_remove.get("573001234567:1").unwrap(), &None);

        let _ = fs::remove_dir_all(&dir).await;
    }
}
