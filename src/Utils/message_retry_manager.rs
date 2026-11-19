use crate::proto::Message;
use crate::utils::generics::now_millis;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const RECENT_MESSAGES_SIZE: usize = 512;
const RECENT_MESSAGES_TTL: Duration = Duration::from_secs(5 * 60);
const MESSAGE_KEY_SEPARATOR: char = '\0';
const RECREATE_SESSION_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const SESSION_HISTORY_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const RETRY_COUNTERS_TTL: Duration = Duration::from_secs(15 * 60);
const BASE_KEYS_MAX: usize = 1024;
const BASE_KEYS_TTL: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_PHONE_REQUEST_DELAY_MS: u64 = 3000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RetryReason {
    UnknownError = 0,
    SignalErrorNoSession = 1,
    SignalErrorInvalidKey = 2,
    SignalErrorInvalidKeyId = 3,
    SignalErrorInvalidMessage = 4,
    SignalErrorInvalidSignature = 5,
    SignalErrorFutureMessage = 6,
    SignalErrorBadMac = 7,
    SignalErrorInvalidSession = 8,
    SignalErrorInvalidMsgKey = 9,
    BadBroadcastEphemeralSetting = 10,
    UnknownCompanionNoPrekey = 11,
    AdvFailure = 12,
    StatusRevokeDelay = 13,
}

impl RetryReason {
    pub fn from_u8(code: u8) -> Self {
        match code {
            0 => Self::UnknownError,
            1 => Self::SignalErrorNoSession,
            2 => Self::SignalErrorInvalidKey,
            3 => Self::SignalErrorInvalidKeyId,
            4 => Self::SignalErrorInvalidMessage,
            5 => Self::SignalErrorInvalidSignature,
            6 => Self::SignalErrorFutureMessage,
            7 => Self::SignalErrorBadMac,
            8 => Self::SignalErrorInvalidSession,
            9 => Self::SignalErrorInvalidMsgKey,
            10 => Self::BadBroadcastEphemeralSetting,
            11 => Self::UnknownCompanionNoPrekey,
            12 => Self::AdvFailure,
            13 => Self::StatusRevokeDelay,
            _ => Self::UnknownError,
        }
    }

    pub fn is_mac_error(self) -> bool {
        matches!(
            self,
            Self::SignalErrorInvalidMessage | Self::SignalErrorBadMac
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecentMessage {
    pub message: Message,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetryStatistics {
    pub total_retries: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub media_retries: u64,
    pub session_recreations: u64,
    pub phone_requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecreateSessionDecision {
    pub reason: String,
    pub recreate: bool,
}

struct TimedEntry<T> {
    value: T,
    updated_at: Instant,
}

struct RetryManagerState {
    recent_messages: HashMap<String, TimedEntry<RecentMessage>>,
    recent_order: VecDeque<String>,
    message_key_index: HashMap<String, String>,
    session_recreate_history: HashMap<String, TimedEntry<u64>>,
    retry_counters: HashMap<String, TimedEntry<u32>>,
    base_keys: HashMap<String, TimedEntry<Vec<u8>>>,
    base_keys_order: VecDeque<String>,
    pending_phone_requests: HashMap<String, JoinHandle<()>>,
    statistics: RetryStatistics,
}

impl RetryManagerState {
    fn new() -> Self {
        Self {
            recent_messages: HashMap::new(),
            recent_order: VecDeque::new(),
            message_key_index: HashMap::new(),
            session_recreate_history: HashMap::new(),
            retry_counters: HashMap::new(),
            base_keys: HashMap::new(),
            base_keys_order: VecDeque::new(),
            pending_phone_requests: HashMap::new(),
            statistics: RetryStatistics::default(),
        }
    }

    fn purge_expired(&mut self) {
        let mut expired_recent = Vec::new();
        for (k, v) in &self.recent_messages {
            if v.updated_at.elapsed() > RECENT_MESSAGES_TTL {
                expired_recent.push(k.clone());
            }
        }
        for k in expired_recent {
            self.remove_recent_by_key(&k);
        }

        self.session_recreate_history
            .retain(|_, v| v.updated_at.elapsed() <= SESSION_HISTORY_TTL);
        self.retry_counters
            .retain(|_, v| v.updated_at.elapsed() <= RETRY_COUNTERS_TTL);
        self.base_keys
            .retain(|_, v| v.updated_at.elapsed() <= BASE_KEYS_TTL);
    }

    fn remove_recent_by_key(&mut self, key_str: &str) {
        self.recent_messages.remove(key_str);
        if let Some(sep_idx) = key_str.rfind(MESSAGE_KEY_SEPARATOR) {
            let msg_id = &key_str[sep_idx + MESSAGE_KEY_SEPARATOR.len_utf8()..];
            self.message_key_index.remove(msg_id);
        }
    }

    fn remove_recent_by_id(&mut self, message_id: &str) {
        if let Some(key_str) = self.message_key_index.remove(message_id) {
            self.recent_messages.remove(&key_str);
        }
    }

    fn cancel_phone_request(&mut self, message_id: &str) {
        if let Some(handle) = self.pending_phone_requests.remove(message_id) {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct MessageRetryManager {
    max_msg_retry_count: u32,
    state: Arc<Mutex<RetryManagerState>>,
}

impl MessageRetryManager {
    pub fn new(max_msg_retry_count: u32) -> Self {
        Self {
            max_msg_retry_count,
            state: Arc::new(Mutex::new(RetryManagerState::new())),
        }
    }

    fn key_to_string(to: &str, id: &str) -> String {
        format!("{}{}{}", to, MESSAGE_KEY_SEPARATOR, id)
    }

    pub fn add_recent_message(&self, to: &str, id: &str, message: Message) {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();

        let key_str = Self::key_to_string(to, id);
        st.recent_messages.insert(
            key_str.clone(),
            TimedEntry {
                value: RecentMessage {
                    message,
                    timestamp: now_millis(),
                },
                updated_at: Instant::now(),
            },
        );
        st.recent_order.push_back(key_str.clone());
        st.message_key_index.insert(id.to_string(), key_str);

        while st.recent_messages.len() > RECENT_MESSAGES_SIZE {
            if let Some(oldest) = st.recent_order.pop_front() {
                st.remove_recent_by_key(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn get_recent_message(&self, to: &str, id: &str) -> Option<RecentMessage> {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        let key_str = Self::key_to_string(to, id);
        st.recent_messages.get(&key_str).map(|e| e.value.clone())
    }

    pub fn should_recreate_session(
        &self,
        jid: &str,
        has_session: bool,
        error_code: Option<RetryReason>,
    ) -> RecreateSessionDecision {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        let now = now_millis();

        if !has_session {
            st.session_recreate_history.insert(
                jid.to_string(),
                TimedEntry {
                    value: now,
                    updated_at: Instant::now(),
                },
            );
            st.statistics.session_recreations += 1;
            return RecreateSessionDecision {
                reason: "we don't have a Signal session with them".to_string(),
                recreate: true,
            };
        }

        if let Some(code) = error_code {
            if code.is_mac_error() {
                st.session_recreate_history.insert(
                    jid.to_string(),
                    TimedEntry {
                        value: now,
                        updated_at: Instant::now(),
                    },
                );
                st.statistics.session_recreations += 1;
                return RecreateSessionDecision {
                    reason: format!(
                        "MAC error (code {}: {:?}), immediate session recreation",
                        code as u8, code
                    ),
                    recreate: true,
                };
            }
        }

        let prev_time = st.session_recreate_history.get(jid).map(|e| e.value);
        let expired = match prev_time {
            None => true,
            Some(prev) => now.saturating_sub(prev) > RECREATE_SESSION_TIMEOUT_MS,
        };

        if expired {
            st.session_recreate_history.insert(
                jid.to_string(),
                TimedEntry {
                    value: now,
                    updated_at: Instant::now(),
                },
            );
            st.statistics.session_recreations += 1;
            return RecreateSessionDecision {
                reason: "retry count > 1 and over an hour since last recreation".to_string(),
                recreate: true,
            };
        }

        RecreateSessionDecision {
            reason: String::new(),
            recreate: false,
        }
    }

    pub fn parse_retry_error_code(error_attr: Option<&str>) -> Option<RetryReason> {
        let raw = error_attr.filter(|s| !s.is_empty())?;
        let code = raw.parse::<i32>().ok()?;
        if (0..=RetryReason::StatusRevokeDelay as i32).contains(&code) {
            Some(RetryReason::from_u8(code as u8))
        } else {
            Some(RetryReason::UnknownError)
        }
    }

    pub fn is_mac_error(error_code: Option<RetryReason>) -> bool {
        error_code.is_some_and(RetryReason::is_mac_error)
    }

    pub fn increment_retry_count(&self, message_id: &str) -> u32 {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        let next = st
            .retry_counters
            .get(message_id)
            .map(|e| e.value)
            .unwrap_or(0)
            + 1;
        st.retry_counters.insert(
            message_id.to_string(),
            TimedEntry {
                value: next,
                updated_at: Instant::now(),
            },
        );
        st.statistics.total_retries += 1;
        next
    }

    pub fn get_retry_count(&self, message_id: &str) -> u32 {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        if let Some(entry) = st.retry_counters.get_mut(message_id) {
            entry.updated_at = Instant::now();
            entry.value
        } else {
            0
        }
    }

    pub fn has_exceeded_max_retries(&self, message_id: &str) -> bool {
        self.get_retry_count(message_id) >= self.max_msg_retry_count
    }

    pub fn mark_retry_success(&self, message_id: &str) {
        let mut st = self.state.lock().unwrap();
        st.statistics.successful_retries += 1;
        st.retry_counters.remove(message_id);
        st.cancel_phone_request(message_id);
        st.remove_recent_by_id(message_id);
    }

    pub fn mark_retry_failed(&self, message_id: &str) {
        let mut st = self.state.lock().unwrap();
        st.statistics.failed_retries += 1;
        st.retry_counters.remove(message_id);
        st.cancel_phone_request(message_id);
        st.remove_recent_by_id(message_id);
    }

    pub fn schedule_phone_request<F>(&self, message_id: String, delay_ms: u64, callback: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut st = self.state.lock().unwrap();
        st.cancel_phone_request(&message_id);

        let state_ref = Arc::clone(&self.state);
        let id_clone = message_id.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            {
                let mut inner = state_ref.lock().unwrap();
                inner.pending_phone_requests.remove(&id_clone);
                inner.statistics.phone_requests += 1;
            }
            callback();
        });

        st.pending_phone_requests.insert(message_id, handle);
    }

    pub fn cancel_pending_phone_request(&self, message_id: &str) {
        let mut st = self.state.lock().unwrap();
        st.cancel_phone_request(message_id);
    }

    pub fn save_base_key(&self, addr: &str, msg_id: &str, base_key: Vec<u8>) {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        let key = format!("{}:{}", addr, msg_id);
        st.base_keys.insert(
            key.clone(),
            TimedEntry {
                value: base_key,
                updated_at: Instant::now(),
            },
        );
        st.base_keys_order.push_back(key);
        while st.base_keys.len() > BASE_KEYS_MAX {
            if let Some(oldest) = st.base_keys_order.pop_front() {
                st.base_keys.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn has_same_base_key(&self, addr: &str, msg_id: &str, base_key: &[u8]) -> bool {
        let mut st = self.state.lock().unwrap();
        st.purge_expired();
        let key = format!("{}:{}", addr, msg_id);
        st.base_keys
            .get(&key)
            .is_some_and(|e| e.value.as_slice() == base_key)
    }

    pub fn delete_base_key(&self, addr: &str, msg_id: &str) {
        let mut st = self.state.lock().unwrap();
        let key = format!("{}:{}", addr, msg_id);
        st.base_keys.remove(&key);
    }

    pub fn statistics(&self) -> RetryStatistics {
        self.state.lock().unwrap().statistics.clone()
    }

    pub fn clear(&self) {
        let mut st = self.state.lock().unwrap();
        st.recent_messages.clear();
        st.recent_order.clear();
        st.message_key_index.clear();
        st.session_recreate_history.clear();
        st.retry_counters.clear();
        st.base_keys.clear();
        st.base_keys_order.clear();
        for (_, handle) in st.pending_phone_requests.drain() {
            handle.abort();
        }
        st.statistics = RetryStatistics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_retry_manager_cache_counts_and_session_recreation() {
        let mgr = MessageRetryManager::new(3);
        let msg = Message {
            conversation: Some("prueba retry".to_string()),
            ..Default::default()
        };

        mgr.add_recent_message("573001@s.whatsapp.net", "ID1", msg.clone());
        assert_eq!(
            mgr.get_recent_message("573001@s.whatsapp.net", "ID1")
                .unwrap()
                .message,
            msg
        );

        assert_eq!(mgr.increment_retry_count("ID1"), 1);
        assert_eq!(mgr.increment_retry_count("ID1"), 2);
        assert!(!mgr.has_exceeded_max_retries("ID1"));
        assert_eq!(mgr.increment_retry_count("ID1"), 3);
        assert!(mgr.has_exceeded_max_retries("ID1"));

        let d1 = mgr.should_recreate_session("573001@s.whatsapp.net", true, None);
        assert!(d1.recreate);
        let d2 = mgr.should_recreate_session("573001@s.whatsapp.net", true, None);
        assert!(!d2.recreate);
        let d3 = mgr.should_recreate_session(
            "573001@s.whatsapp.net",
            true,
            Some(RetryReason::SignalErrorBadMac),
        );
        assert!(d3.recreate);

        assert_eq!(
            MessageRetryManager::parse_retry_error_code(Some("7")),
            Some(RetryReason::SignalErrorBadMac)
        );
        assert!(MessageRetryManager::is_mac_error(Some(
            RetryReason::SignalErrorInvalidMessage
        )));

        mgr.save_base_key("573001.0", "ID1", vec![1, 2, 3]);
        assert!(mgr.has_same_base_key("573001.0", "ID1", &[1, 2, 3]));
        mgr.delete_base_key("573001.0", "ID1");
        assert!(!mgr.has_same_base_key("573001.0", "ID1", &[1, 2, 3]));

        mgr.mark_retry_success("ID1");
        assert!(mgr.get_recent_message("573001@s.whatsapp.net", "ID1").is_none());
        assert_eq!(mgr.get_retry_count("ID1"), 0);
    }

    #[tokio::test]
    async fn test_schedule_and_cancel_phone_request() {
        let mgr = MessageRetryManager::new(5);
        let ran_cancelled = Arc::new(AtomicBool::new(false));
        let flag1 = Arc::clone(&ran_cancelled);
        mgr.schedule_phone_request("CANCEL_ME".to_string(), 40, move || {
            flag1.store(true, Ordering::SeqCst);
        });
        mgr.cancel_pending_phone_request("CANCEL_ME");

        let ran_ok = Arc::new(AtomicBool::new(false));
        let flag2 = Arc::clone(&ran_ok);
        mgr.schedule_phone_request("RUN_ME".to_string(), 15, move || {
            flag2.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!ran_cancelled.load(Ordering::SeqCst));
        assert!(ran_ok.load(Ordering::SeqCst));
        assert_eq!(mgr.statistics().phone_requests, 1);
    }
}
