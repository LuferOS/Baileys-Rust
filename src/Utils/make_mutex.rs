use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone, Default)]
pub struct AsyncMutexLock {
    mutex: Arc<AsyncMutex<()>>,
}

impl AsyncMutexLock {
    pub fn new() -> Self {
        Self {
            mutex: Arc::new(AsyncMutex::new(())),
        }
    }

    pub async fn mutex<F, Fut, T>(&self, code: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let _guard = self.mutex.lock().await;
        code().await
    }
}

struct KeyedEntry {
    mutex: Arc<AsyncMutex<()>>,
    ref_count: usize,
}

struct KeyedMutexRefGuard {
    map: Arc<StdMutex<HashMap<String, KeyedEntry>>>,
    key: String,
    mutex: Arc<AsyncMutex<()>>,
}

impl Drop for KeyedMutexRefGuard {
    fn drop(&mut self) {
        let mut guard = self.map.lock().unwrap();
        let should_remove = if let Some(entry) = guard.get_mut(&self.key) {
            if Arc::ptr_eq(&entry.mutex, &self.mutex) {
                entry.ref_count = entry.ref_count.saturating_sub(1);
                entry.ref_count == 0
            } else {
                false
            }
        } else {
            false
        };
        if should_remove {
            guard.remove(&self.key);
        }
    }
}

#[derive(Clone, Default)]
pub struct KeyedMutex {
    map: Arc<StdMutex<HashMap<String, KeyedEntry>>>,
}

impl KeyedMutex {
    pub fn new() -> Self {
        Self {
            map: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    pub async fn mutex<F, Fut, T>(&self, key: &str, task: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let entry_mutex = {
            let mut guard = self.map.lock().unwrap();
            let entry = guard
                .entry(key.to_string())
                .or_insert_with(|| KeyedEntry {
                    mutex: Arc::new(AsyncMutex::new(())),
                    ref_count: 0,
                });
            entry.ref_count += 1;
            Arc::clone(&entry.mutex)
        };

        let _ref_guard = KeyedMutexRefGuard {
            map: Arc::clone(&self.map),
            key: key.to_string(),
            mutex: Arc::clone(&entry_mutex),
        };

        let _lock = entry_mutex.lock().await;
        task().await
    }

    pub fn active_keys(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_mutex_lock_serializes() {
        let lock = AsyncMutexLock::new();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let l = lock.clone();
            let cur = Arc::clone(&in_flight);
            let max_s = Arc::clone(&max_seen);
            handles.push(tokio::spawn(async move {
                l.mutex(|| async move {
                    let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    max_s.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    cur.fetch_sub(1, Ordering::SeqCst);
                })
                .await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(max_seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_keyed_mutex_isolation_and_cleanup() {
        let km = KeyedMutex::new();
        let active_same = Arc::new(AtomicUsize::new(0));
        let max_same = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = km.clone();
            let cur = Arc::clone(&active_same);
            let max_s = Arc::clone(&max_same);
            handles.push(tokio::spawn(async move {
                m.mutex("user-a", || async move {
                    let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    max_s.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    cur.fetch_sub(1, Ordering::SeqCst);
                })
                .await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(max_same.load(Ordering::SeqCst), 1);
        assert_eq!(km.active_keys(), 0);
    }
}
