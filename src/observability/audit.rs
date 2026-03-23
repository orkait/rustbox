use crate::config::types::{IsolateError, Result};
use log::{error, info, warn};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityEventType {
    CommandInjectionAttempt,
    PathTraversalAttempt,
}

impl SecurityEventType {
    fn default_severity(&self) -> SecuritySeverity {
        match self {
            SecurityEventType::CommandInjectionAttempt => SecuritySeverity::Critical,
            SecurityEventType::PathTraversalAttempt => SecuritySeverity::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub timestamp: SystemTime,
    pub details: String,
    pub box_id: Option<u32>,
    pub command: Option<String>,
    pub file_path: Option<String>,
}

impl SecurityEvent {
    fn new(event_type: SecurityEventType, details: &str) -> Self {
        let severity = event_type.default_severity();
        Self {
            event_type,
            severity,
            timestamp: SystemTime::now(),
            details: details.to_owned(),
            box_id: None,
            command: None,
            file_path: None,
        }
    }
}

pub struct SecurityLogger {
    audit_file: Arc<Mutex<File>>,
}

impl SecurityLogger {
    fn new(audit_path: Option<PathBuf>) -> Result<Self> {
        let audit_path = audit_path.unwrap_or_else(|| {
            std::env::temp_dir()
                .join("rustbox")
                .join("security-audit.log")
        });

        if let Some(parent) = audit_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                IsolateError::Config(format!("Failed to create security log directory: {}", e))
            })?;
        }

        let audit_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .map_err(|e| {
                IsolateError::Config(format!("Failed to open security audit log: {}", e))
            })?;

        Ok(Self {
            audit_file: Arc::new(Mutex::new(audit_file)),
        })
    }

    fn log_event(&self, event: &SecurityEvent) {
        let log_entry = serde_json::json!({
            "timestamp": event.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "event_type": event.event_type,
            "severity": event.severity,
            "details": event.details,
            "process_id": std::process::id(),
            "box_id": event.box_id,
            "command": event.command,
            "file_path": event.file_path,
        });

        match event.severity {
            SecuritySeverity::Critical | SecuritySeverity::High => {
                error!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
            SecuritySeverity::Medium => {
                warn!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
            SecuritySeverity::Low => {
                info!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
        }

        if let Ok(mut file) = self.audit_file.lock() {
            let _ = writeln!(file, "{}", log_entry);
            let _ = file.flush();
        }
    }
}

static SECURITY_LOGGER: OnceLock<SecurityLogger> = OnceLock::new();

pub fn init_security_logger(audit_path: Option<PathBuf>) -> Result<()> {
    match SecurityLogger::new(audit_path.clone()) {
        Ok(logger) => {
            let _ = SECURITY_LOGGER.set(logger);
        }
        Err(e) => {
            if audit_path.is_none() {
                let fallback_paths = [
                    std::env::temp_dir().join(format!("rustbox-security-audit-{}.log", unsafe {
                        libc::geteuid()
                    })),
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(std::env::temp_dir)
                        .join(".rustbox")
                        .join("security-audit.log"),
                ];

                for fallback in &fallback_paths {
                    if let Ok(logger) = SecurityLogger::new(Some(fallback.clone())) {
                        let _ = SECURITY_LOGGER.set(logger);
                        return Ok(());
                    }
                }

                warn!("Security logger unavailable (all paths failed): {}", e);
                return Ok(());
            }

            error!("Failed to initialize security logger: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

fn log_security_event(event: SecurityEvent) {
    if let Some(logger) = SECURITY_LOGGER.get() {
        logger.log_event(&event);
    } else {
        match event.severity {
            SecuritySeverity::Critical | SecuritySeverity::High => {
                error!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
            SecuritySeverity::Medium => {
                warn!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
            SecuritySeverity::Low => {
                info!("SECURITY: {:?} - {}", event.event_type, event.details);
            }
        }
    }
}

pub mod events {
    use super::*;

    pub fn command_injection_attempt(command: &str, box_id: Option<u32>) {
        let mut event = SecurityEvent::new(
            SecurityEventType::CommandInjectionAttempt,
            &format!("Blocked potentially malicious command: {}", command),
        );
        event.command = Some(command.to_owned());
        event.box_id = box_id;
        log_security_event(event);
    }

    pub fn path_traversal_attempt(path: &str, box_id: Option<u32>) {
        let mut event = SecurityEvent::new(
            SecurityEventType::PathTraversalAttempt,
            &format!("Blocked path traversal attempt: {}", path),
        );
        event.file_path = Some(path.to_owned());
        event.box_id = box_id;
        log_security_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_serialization() {
        let event = SecurityEvent::new(SecurityEventType::CommandInjectionAttempt, "test");
        assert!(serde_json::to_string(&event).is_ok());
    }

    #[test]
    fn test_security_logger_creation() {
        let audit_path = std::env::temp_dir().join("rustbox-test-audit.log");
        let logger = SecurityLogger::new(Some(audit_path.clone()));
        assert!(logger.is_ok());
        let _ = std::fs::remove_file(audit_path);
    }
}
