use baileys_rs::utils::unix_timestamp_seconds;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;

const MAX_HISTORY: usize = 25;

pub struct DebugSnapshot {
    pub enabled: bool,
    pub socket_lagged: u64,
    pub recv_lagged: u64,
    pub active_tasks: usize,
    pub total_commands: u64,
    pub total_errors: u64,
    pub last_errors: Vec<String>,
    pub last_timings: Vec<String>,
}

pub struct DebugState {
    enabled: AtomicBool,
    pub socket_lagged: AtomicU64,
    pub recv_lagged: AtomicU64,
    pub active_tasks: AtomicUsize,
    pub total_commands: AtomicU64,
    pub total_errors: AtomicU64,
    last_errors: RwLock<VecDeque<String>>,
    last_timings: RwLock<VecDeque<String>>,
}

impl DebugState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            socket_lagged: AtomicU64::new(0),
            recv_lagged: AtomicU64::new(0),
            active_tasks: AtomicUsize::new(0),
            total_commands: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            last_errors: RwLock::new(VecDeque::with_capacity(MAX_HISTORY)),
            last_timings: RwLock::new(VecDeque::with_capacity(MAX_HISTORY)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, value: bool) {
        self.enabled.store(value, Ordering::Relaxed);
    }

    pub fn log(&self, scope: &str, msg: impl AsRef<str>) {
        if self.is_enabled() {
            println!("[debug][{}][{}] {}", unix_timestamp_seconds(), scope, msg.as_ref());
        }
    }

    pub async fn record_error(&self, scope: &str, err: impl AsRef<str>) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
        let entry = format!("[{}][{}] {}", unix_timestamp_seconds(), scope, err.as_ref());
        eprintln!("[error]{}", entry);
        let mut guard = self.last_errors.write().await;
        if guard.len() >= MAX_HISTORY {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    pub async fn record_timing(&self, scope: &str, detail: impl AsRef<str>) {
        let entry = format!("[{}][{}] {}", unix_timestamp_seconds(), scope, detail.as_ref());
        if self.is_enabled() {
            println!("[perf]{}", entry);
        }
        let mut guard = self.last_timings.write().await;
        if guard.len() >= MAX_HISTORY {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    pub async fn clear(&self) {
        self.last_errors.write().await.clear();
        self.last_timings.write().await.clear();
        self.socket_lagged.store(0, Ordering::Relaxed);
        self.recv_lagged.store(0, Ordering::Relaxed);
        self.total_errors.store(0, Ordering::Relaxed);
    }

    pub async fn snapshot(&self) -> DebugSnapshot {
        let errors = self.last_errors.read().await.iter().cloned().collect();
        let timings = self.last_timings.read().await.iter().cloned().collect();
        DebugSnapshot {
            enabled: self.is_enabled(),
            socket_lagged: self.socket_lagged.load(Ordering::Relaxed),
            recv_lagged: self.recv_lagged.load(Ordering::Relaxed),
            active_tasks: self.active_tasks.load(Ordering::Relaxed),
            total_commands: self.total_commands.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            last_errors: errors,
            last_timings: timings,
        }
    }
}
