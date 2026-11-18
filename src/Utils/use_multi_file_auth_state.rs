use crate::types::{init_auth_creds, AuthenticationCreds};
use crate::utils::crypto::CryptoError;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::Mutex;

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

pub struct MultiFileAuthState {
    folder: PathBuf,
    pub creds: AuthenticationCreds,
    file_locks: Arc<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>>,
}

fn fix_file_name(file: &str) -> String {
    file.replace('/', "__").replace(':', "-")
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

        let file_locks = Arc::new(Mutex::new(HashMap::new()));
        let mut state = Self {
            folder,
            creds: init_auth_creds()?,
            file_locks,
        };

        if let Some(loaded) = state.read_data::<AuthenticationCreds>("creds.json").await {
            state.creds = loaded;
        }

        Ok(state)
    }

    async fn get_file_lock(&self, path: &Path) -> Arc<Mutex<()>> {
        let mut locks = self.file_locks.lock().await;
        locks
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn write_data<T: Serialize>(&self, data: &T, file: &str) -> Result<(), AuthStateError> {
        let file_path = self.folder.join(fix_file_name(file));
        let mutex = self.get_file_lock(&file_path).await;
        let _guard = mutex.lock().await;
        let serialized = serde_json::to_string(data)?;
        fs::write(&file_path, serialized).await?;
        Ok(())
    }

    async fn read_data<T: DeserializeOwned>(&self, file: &str) -> Option<T> {
        let file_path = self.folder.join(fix_file_name(file));
        let mutex = self.get_file_lock(&file_path).await;
        let _guard = mutex.lock().await;
        let raw = fs::read_to_string(&file_path).await.ok()?;
        serde_json::from_str(&raw).ok()
    }

    async fn remove_data(&self, file: &str) {
        let file_path = self.folder.join(fix_file_name(file));
        let mutex = self.get_file_lock(&file_path).await;
        let _guard = mutex.lock().await;
        let _ = fs::remove_file(&file_path).await;
    }

    pub async fn save_creds(&self) -> Result<(), AuthStateError> {
        self.write_data(&self.creds, "creds.json").await
    }

    pub async fn get_keys(&self, key_type: &str, ids: &[String]) -> HashMap<String, Option<Value>> {
        let mut result = HashMap::with_capacity(ids.len());
        for id in ids {
            let file = format!("{}-{}.json", key_type, id);
            let value = self.read_data::<Value>(&file).await;
            result.insert(id.clone(), value);
        }
        result
    }

    pub async fn set_keys(
        &self,
        data: HashMap<String, HashMap<String, Option<Value>>>,
    ) -> Result<(), AuthStateError> {
        for (category, entries) in data {
            for (id, value) in entries {
                let file = format!("{}-{}.json", category, id);
                match value {
                    Some(v) => self.write_data(&v, &file).await?,
                    None => self.remove_data(&file).await,
                }
            }
        }
        Ok(())
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
