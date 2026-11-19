use crate::utils::generics::now_millis;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace = 10,
    Debug = 20,
    Info = 30,
    Warn = 40,
    Error = 50,
    Silent = 100,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Silent => "silent",
        }
    }

    pub fn from_str_level(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "silent" | "off" => LogLevel::Silent,
            _ => LogLevel::Info,
        }
    }
}

pub trait Logger: Send + Sync {
    fn level(&self) -> LogLevel;
    fn child(&self, bindings: Map<String, Value>) -> Arc<dyn Logger>;
    fn log(&self, level: LogLevel, fields: Option<&Value>, msg: &str);

    fn trace(&self, fields: Option<&Value>, msg: &str) {
        self.log(LogLevel::Trace, fields, msg);
    }

    fn debug(&self, fields: Option<&Value>, msg: &str) {
        self.log(LogLevel::Debug, fields, msg);
    }

    fn info(&self, fields: Option<&Value>, msg: &str) {
        self.log(LogLevel::Info, fields, msg);
    }

    fn warn(&self, fields: Option<&Value>, msg: &str) {
        self.log(LogLevel::Warn, fields, msg);
    }

    fn error(&self, fields: Option<&Value>, msg: &str) {
        self.log(LogLevel::Error, fields, msg);
    }
}

#[derive(Debug, Clone)]
pub struct BaileysLogger {
    level: LogLevel,
    bindings: Map<String, Value>,
}

impl Default for BaileysLogger {
    fn default() -> Self {
        Self::new(LogLevel::Info)
    }
}

impl BaileysLogger {
    pub fn new(level: LogLevel) -> Self {
        Self {
            level,
            bindings: Map::new(),
        }
    }

    pub fn silent() -> Self {
        Self::new(LogLevel::Silent)
    }

    pub fn format_record(&self, level: LogLevel, fields: Option<&Value>, msg: &str) -> String {
        let mut obj = self.bindings.clone();
        obj.insert("level".to_string(), Value::String(level.as_str().to_string()));
        obj.insert("time".to_string(), Value::Number(now_millis().into()));
        if let Some(f) = fields {
            if let Some(map) = f.as_object() {
                for (k, v) in map {
                    obj.insert(k.clone(), v.clone());
                }
            } else {
                obj.insert("data".to_string(), f.clone());
            }
        }
        if !msg.is_empty() {
            obj.insert("msg".to_string(), Value::String(msg.to_string()));
        }
        Value::Object(obj).to_string()
    }
}

impl Logger for BaileysLogger {
    fn level(&self) -> LogLevel {
        self.level
    }

    fn child(&self, bindings: Map<String, Value>) -> Arc<dyn Logger> {
        let mut merged = self.bindings.clone();
        for (k, v) in bindings {
            merged.insert(k, v);
        }
        Arc::new(BaileysLogger {
            level: self.level,
            bindings: merged,
        })
    }

    fn log(&self, level: LogLevel, fields: Option<&Value>, msg: &str) {
        if level < self.level || self.level == LogLevel::Silent {
            return;
        }
        eprintln!("{}", self.format_record(level, fields, msg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_logger_levels_and_child() {
        assert_eq!(LogLevel::from_str_level("debug"), LogLevel::Debug);
        assert!(LogLevel::Trace < LogLevel::Info);

        let base = BaileysLogger::new(LogLevel::Info);
        let line = base.format_record(LogLevel::Info, Some(&json!({"jid": "123"})), "connected");
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["level"], "info");
        assert_eq!(parsed["jid"], "123");
        assert_eq!(parsed["msg"], "connected");

        let mut bindings = Map::new();
        bindings.insert("module".to_string(), Value::String("socket".to_string()));
        let child = base.child(bindings);
        assert_eq!(child.level(), LogLevel::Info);
    }
}
