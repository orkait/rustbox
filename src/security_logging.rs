/// Security event logging framework for rustbox
/// Provides structured logging of security-relevant events for compliance and incident response
use crate::types::{IsolateError, Result};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Types of security events we track
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    CommandInjectionAttempt,
    PathTraversalAttempt,
    ResourceLimitExceeded,
    UnauthorizedFileAccess,
    SuspiciousCommand,
    ChrootEscape,
    NamespaceViolation,
    LockManagerViolation,
    ConfigurationViolation,
    ProcessEscalation,
}

impl SecurityEventType {
    /// Get the default severity for this event type
    pub fn default_severity(&self) -> SecuritySeverity {
        match self {
            SecurityEventType::CommandInjectionAttempt => SecuritySeverity::Critical,
            SecurityEventType::PathTraversalAttempt => SecuritySeverity::Critical,
            SecurityEventType::ChrootEscape => SecuritySeverity::Critical,
            SecurityEventType::ProcessEscalation => SecuritySeverity::Critical,
            SecurityEventType::NamespaceViolation => SecuritySeverity::High,
            SecurityEventType::ResourceLimitExceeded => SecuritySeverity::High,
            SecurityEventType::UnauthorizedFileAccess => SecuritySeverity::High,
            SecurityEventType::LockManagerViolation => SecuritySeverity::Medium,
            SecurityEventType::SuspiciousCommand => SecuritySeverity::Medium,
            SecurityEventType::ConfigurationViolation => SecuritySeverity::Low,
        }
    }
}

/// Individual security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub box_id: Option<u32>,
    pub details: String,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
    pub timestamp: SystemTime,
    pub command: Option<String>,
    pub file_path: Option<String>,
}

impl SecurityEvent {
    /// Create a new security event with default severity
    pub fn new(event_type: SecurityEventType, details: String) -> Self {
        let severity = event_type.default_severity();
        Self {
            event_type,
            severity,
            box_id: None,
            details,
            source_ip: None,
            user_id: None,
            timestamp: SystemTime::now(),
            command: None,
            file_path: None,
        }
    }

    /// Builder pattern methods for optional fields
    pub fn with_box_id(mut self, box_id: u32) -> Self {
        self.box_id = Some(box_id);
        self
    }

    pub fn with_command(mut self, command: String) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_file_path(mut self, file_path: String) -> Self {
        self.file_path = Some(file_path);
        self
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Security logger that handles both structured logging and audit trail
pub struct SecurityLogger {
    audit_file: Arc<Mutex<File>>,
    audit_path: PathBuf,
}

impl SecurityLogger {
    /// Create a new security logger
    pub fn new(audit_path: Option<PathBuf>) -> Result<Self> {
        let audit_path = audit_path.unwrap_or_else(|| {
            std::env::temp_dir()
                .join("rustbox")
                .join("security-audit.log")
        });

        // Ensure parent directory exists
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
            audit_path,
        })
    }

    /// Log a security event
    pub fn log_security_event(&self, event: SecurityEvent) {
        // Create structured log entry
        let log_entry = serde_json::json!({
            "timestamp": event.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "event_type": event.event_type,
            "severity": event.severity,
            "box_id": event.box_id,
            "details": event.details,
            "source_ip": event.source_ip,
            "user_id": event.user_id,
            "command": event.command,
            "file_path": event.file_path,
            "process_id": std::process::id(),
        });

        // Log to standard logger based on severity
        match event.severity {
            SecuritySeverity::Critical => {
                error!(
                    "SECURITY CRITICAL: {} - {}",
                    format!("{:?}", event.event_type),
                    event.details
                );
            }
            SecuritySeverity::High => {
                error!(
                    "SECURITY HIGH: {} - {}",
                    format!("{:?}", event.event_type),
                    event.details
                );
            }
            SecuritySeverity::Medium => {
                warn!(
                    "SECURITY MEDIUM: {} - {}",
                    format!("{:?}", event.event_type),
                    event.details
                );
            }
            SecuritySeverity::Low => {
                info!(
                    "SECURITY LOW: {} - {}",
                    format!("{:?}", event.event_type),
                    event.details
                );
            }
        }

        // Write to audit file for compliance
        if let Ok(mut file) = self.audit_file.lock() {
            if let Err(e) = writeln!(file, "{}", log_entry) {
                error!("Failed to write to security audit log: {}", e);
            }
            if let Err(e) = file.flush() {
                error!("Failed to flush security audit log: {}", e);
            }
        } else {
            error!("Failed to acquire lock on security audit file");
        }
    }

    /// Get the audit log file path
    pub fn audit_path(&self) -> &PathBuf {
        &self.audit_path
    }
}

/// Global security logger instance
static SECURITY_LOGGER: OnceLock<SecurityLogger> = OnceLock::new();

/// Initialize the global security logger
pub fn init_security_logger(audit_path: Option<PathBuf>) -> Result<()> {
    match SecurityLogger::new(audit_path) {
        Ok(logger) => {
            if SECURITY_LOGGER.set(logger).is_err() {
                error!("Security logger already initialized");
            } else {
                info!("Security logger initialized");
            }
        }
        Err(e) => {
            error!("Failed to initialize security logger: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

/// Log a security event using the global logger
pub fn log_security_event(event: SecurityEvent) {
    if let Some(logger) = SECURITY_LOGGER.get() {
        logger.log_security_event(event);
    } else {
        // Fallback to standard logging if security logger not initialized
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

/// Convenience functions for common security events
pub mod events {
    use super::*;

    /// Log a command injection attempt
    pub fn command_injection_attempt(command: String, box_id: Option<u32>) {
        let event = SecurityEvent::new(
            SecurityEventType::CommandInjectionAttempt,
            format!("Blocked potentially malicious command: {}", command),
        )
        .with_command(command);

        let event = if let Some(id) = box_id {
            event.with_box_id(id)
        } else {
            event
        };

        log_security_event(event);
    }

    /// Log a path traversal attempt
    pub fn path_traversal_attempt(path: String, box_id: Option<u32>) {
        let event = SecurityEvent::new(
            SecurityEventType::PathTraversalAttempt,
            format!("Blocked path traversal attempt: {}", path),
        )
        .with_file_path(path);

        let event = if let Some(id) = box_id {
            event.with_box_id(id)
        } else {
            event
        };

        log_security_event(event);
    }

    /// Log a resource limit violation
    pub fn resource_limit_exceeded(resource: String, limit: String, box_id: Option<u32>) {
        let event = SecurityEvent::new(
            SecurityEventType::ResourceLimitExceeded,
            format!("Resource limit exceeded: {} > {}", resource, limit),
        );

        let event = if let Some(id) = box_id {
            event.with_box_id(id)
        } else {
            event
        };

        log_security_event(event);
    }

    /// Log unauthorized file access attempt
    pub fn unauthorized_file_access(file_path: String, box_id: Option<u32>) {
        let event = SecurityEvent::new(
            SecurityEventType::UnauthorizedFileAccess,
            format!("Blocked unauthorized file access: {}", file_path),
        )
        .with_file_path(file_path);

        let event = if let Some(id) = box_id {
            event.with_box_id(id)
        } else {
            event
        };

        log_security_event(event);
    }

    /// Log suspicious command execution
    pub fn suspicious_command(command: String, reason: String, box_id: Option<u32>) {
        let event = SecurityEvent::new(
            SecurityEventType::SuspiciousCommand,
            format!("Suspicious command detected ({}): {}", reason, command),
        )
        .with_command(command);

        let event = if let Some(id) = box_id {
            event.with_box_id(id)
        } else {
            event
        };

        log_security_event(event);
    }
}