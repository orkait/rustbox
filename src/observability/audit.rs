/// Security event logging framework for rustbox
/// Provides structured logging of security-relevant events for compliance and incident response
///
/// P2-AUDIT-001: Structured Event Schema v1
/// - Correlation IDs (request_id, run_id, box_id, root PID/session)
/// - Event types: start, capability decision, limit violations, signal escalation, cleanup outcome, final status
/// - Integration with provenance and envelope systems
use crate::config::types::{CapabilityReport, IsolateError, Result, VerdictProvenance};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use uuid::Uuid;

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Types of security events we track (P2-AUDIT-001)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    // Lifecycle events
    ExecutionStart,
    ExecutionEnd,

    // Capability and control events
    CapabilityDecision,
    ControlDegraded,

    // Limit violation events
    MemoryLimitViolation,
    CpuLimitViolation,
    WallTimeLimitViolation,
    ProcessLimitViolation,
    OutputLimitViolation,

    // Signal and termination events
    SignalEscalation,
    GracefulKill,
    ForcedKill,

    // Cleanup events
    CleanupStart,
    CleanupSuccess,
    CleanupFailure,
    CleanupPartial,

    // Legacy security events
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

/// Correlation identifiers for event tracking (P2-AUDIT-001)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationIds {
    /// Unique request identifier (spans multiple runs if adaptive rerun enabled)
    pub request_id: String,
    /// Unique run identifier (specific to this execution attempt)
    pub run_id: String,
    /// Box identifier (isolate instance)
    pub box_id: u32,
    /// Root PID in host namespace
    pub root_pid: Option<u32>,
    /// Session ID
    pub session_id: Option<u32>,
}

impl CorrelationIds {
    /// Create new correlation IDs for a run
    pub fn new(box_id: u32) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            run_id: Uuid::new_v4().to_string(),
            box_id,
            root_pid: None,
            session_id: None,
        }
    }

    /// Set root PID after process spawn
    pub fn with_root_pid(mut self, pid: u32) -> Self {
        self.root_pid = Some(pid);
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, sid: u32) -> Self {
        self.session_id = Some(sid);
        self
    }
}

impl SecurityEventType {
    /// Get the default severity for this event type
    pub fn default_severity(&self) -> SecuritySeverity {
        match self {
            // Critical lifecycle events
            SecurityEventType::ExecutionStart => SecuritySeverity::Low,
            SecurityEventType::ExecutionEnd => SecuritySeverity::Low,

            // Capability events
            SecurityEventType::CapabilityDecision => SecuritySeverity::Medium,
            SecurityEventType::ControlDegraded => SecuritySeverity::High,

            // Limit violations
            SecurityEventType::MemoryLimitViolation => SecuritySeverity::High,
            SecurityEventType::CpuLimitViolation => SecuritySeverity::High,
            SecurityEventType::WallTimeLimitViolation => SecuritySeverity::High,
            SecurityEventType::ProcessLimitViolation => SecuritySeverity::High,
            SecurityEventType::OutputLimitViolation => SecuritySeverity::Medium,

            // Signal events
            SecurityEventType::SignalEscalation => SecuritySeverity::High,
            SecurityEventType::GracefulKill => SecuritySeverity::Medium,
            SecurityEventType::ForcedKill => SecuritySeverity::High,

            // Cleanup events
            SecurityEventType::CleanupStart => SecuritySeverity::Low,
            SecurityEventType::CleanupSuccess => SecuritySeverity::Low,
            SecurityEventType::CleanupFailure => SecuritySeverity::Critical,
            SecurityEventType::CleanupPartial => SecuritySeverity::High,

            // Legacy security events
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

/// Individual security event (P2-AUDIT-001 enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub timestamp: SystemTime,
    pub details: String,

    // Correlation identifiers (P2-AUDIT-001)
    pub correlation: Option<CorrelationIds>,

    // Capability and provenance context (P2-AUDIT-001)
    pub capability_report: Option<CapabilityReport>,
    pub verdict_provenance: Option<VerdictProvenance>,
    pub envelope_id: Option<String>,

    // Legacy fields
    pub box_id: Option<u32>,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
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
            timestamp: SystemTime::now(),
            details,
            correlation: None,
            capability_report: None,
            verdict_provenance: None,
            envelope_id: None,
            box_id: None,
            source_ip: None,
            user_id: None,
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

    /// P2-AUDIT-001: Add correlation IDs
    pub fn with_correlation(mut self, correlation: CorrelationIds) -> Self {
        self.correlation = Some(correlation);
        self
    }

    /// P2-AUDIT-001: Add capability report
    pub fn with_capability_report(mut self, report: CapabilityReport) -> Self {
        self.capability_report = Some(report);
        self
    }

    /// P2-AUDIT-001: Add verdict provenance
    pub fn with_verdict_provenance(mut self, provenance: VerdictProvenance) -> Self {
        self.verdict_provenance = Some(provenance);
        self
    }

    /// P2-AUDIT-001: Add execution envelope ID
    pub fn with_envelope_id(mut self, envelope_id: String) -> Self {
        self.envelope_id = Some(envelope_id);
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

    /// Log a security event (P2-AUDIT-001 enhanced)
    pub fn log_security_event(&self, event: SecurityEvent) {
        // Create structured log entry with P2-AUDIT-001 fields
        let mut log_entry = serde_json::json!({
            "timestamp": event.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "event_type": event.event_type,
            "severity": event.severity,
            "details": event.details,
            "process_id": std::process::id(),
        });

        // Add correlation IDs if present (P2-AUDIT-001)
        if let Some(correlation) = &event.correlation {
            log_entry["correlation"] = serde_json::json!({
                "request_id": correlation.request_id,
                "run_id": correlation.run_id,
                "box_id": correlation.box_id,
                "root_pid": correlation.root_pid,
                "session_id": correlation.session_id,
            });
        }

        // Add capability report if present (P2-AUDIT-001)
        if let Some(capability_report) = &event.capability_report {
            log_entry["capability_report"] =
                serde_json::to_value(capability_report).unwrap_or_else(|_| serde_json::json!(null));
        }

        // Add verdict provenance if present (P2-AUDIT-001)
        if let Some(verdict_provenance) = &event.verdict_provenance {
            log_entry["verdict_provenance"] = serde_json::to_value(verdict_provenance)
                .unwrap_or_else(|_| serde_json::json!(null));
        }

        // Add envelope ID if present (P2-AUDIT-001)
        if let Some(envelope_id) = &event.envelope_id {
            log_entry["envelope_id"] = serde_json::json!(envelope_id);
        }

        // Add legacy fields if present
        if let Some(box_id) = event.box_id {
            log_entry["box_id"] = serde_json::json!(box_id);
        }
        if let Some(source_ip) = &event.source_ip {
            log_entry["source_ip"] = serde_json::json!(source_ip);
        }
        if let Some(user_id) = &event.user_id {
            log_entry["user_id"] = serde_json::json!(user_id);
        }
        if let Some(command) = &event.command {
            log_entry["command"] = serde_json::json!(command);
        }
        if let Some(file_path) = &event.file_path {
            log_entry["file_path"] = serde_json::json!(file_path);
        }

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
    match SecurityLogger::new(audit_path.clone()) {
        Ok(logger) => {
            if SECURITY_LOGGER.set(logger).is_err() {
                error!("Security logger already initialized");
            } else {
                info!("Security logger initialized");
            }
        }
        Err(e) => {
            // If caller did not force a path, attempt user-writable fallback paths.
            if audit_path.is_none() {
                let fallback_paths = vec![
                    std::env::temp_dir().join(format!("rustbox-security-audit-{}.log", unsafe {
                        libc::geteuid()
                    })),
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(std::env::temp_dir)
                        .join(".rustbox")
                        .join("security-audit.log"),
                ];

                for fallback in fallback_paths {
                    match SecurityLogger::new(Some(fallback.clone())) {
                        Ok(logger) => {
                            if SECURITY_LOGGER.set(logger).is_err() {
                                error!("Security logger already initialized");
                            } else {
                                warn!(
                                    "Security logger initialized using fallback path: {}",
                                    fallback.display()
                                );
                            }
                            return Ok(());
                        }
                        Err(fallback_err) => {
                            warn!(
                                "Failed to initialize fallback security logger at {}: {}",
                                fallback.display(),
                                fallback_err
                            );
                        }
                    }
                }

                // Degrade gracefully: run without file-backed audit logger.
                warn!(
                    "Security logger unavailable (all paths failed). Continuing with stderr-only security events: {}",
                    e
                );
                return Ok(());
            }

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

/// Log execution start event
pub fn execution_start(
    correlation: CorrelationIds,
    envelope_id: String,
    capability_report: CapabilityReport,
) {
    let event = SecurityEvent::new(
        SecurityEventType::ExecutionStart,
        format!("Execution started: run_id={}", correlation.run_id),
    )
    .with_correlation(correlation)
    .with_envelope_id(envelope_id)
    .with_capability_report(capability_report);

    log_security_event(event);
}

/// Log execution end event
pub fn execution_end(correlation: CorrelationIds, verdict_provenance: VerdictProvenance) {
    let event = SecurityEvent::new(
        SecurityEventType::ExecutionEnd,
        format!(
            "Execution ended: run_id={}, status={:?}, actor={:?}",
            correlation.run_id, verdict_provenance.verdict_actor, verdict_provenance.verdict_cause
        ),
    )
    .with_correlation(correlation)
    .with_verdict_provenance(verdict_provenance);

    log_security_event(event);
}

/// Log capability decision event
pub fn capability_decision(
    correlation: CorrelationIds,
    capability_report: CapabilityReport,
    decision: String,
) {
    let event = SecurityEvent::new(
        SecurityEventType::CapabilityDecision,
        format!("Capability decision: {}", decision),
    )
    .with_correlation(correlation)
    .with_capability_report(capability_report);

    log_security_event(event);
}

/// Log control degraded event
pub fn control_degraded(correlation: CorrelationIds, control_name: String, reason: String) {
    let event = SecurityEvent::new(
        SecurityEventType::ControlDegraded,
        format!("Control degraded: {} - {}", control_name, reason),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

// P2-AUDIT-001: Limit violation event helpers

/// Log memory limit violation
pub fn memory_limit_violation(correlation: CorrelationIds, used: u64, limit: u64) {
    let event = SecurityEvent::new(
        SecurityEventType::MemoryLimitViolation,
        format!(
            "Memory limit violated: used={} bytes, limit={} bytes",
            used, limit
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log CPU limit violation
pub fn cpu_limit_violation(correlation: CorrelationIds, used_ms: u64, limit_ms: u64) {
    let event = SecurityEvent::new(
        SecurityEventType::CpuLimitViolation,
        format!(
            "CPU limit violated: used={} ms, limit={} ms",
            used_ms, limit_ms
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log wall time limit violation
pub fn wall_time_limit_violation(correlation: CorrelationIds, used_ms: u64, limit_ms: u64) {
    let event = SecurityEvent::new(
        SecurityEventType::WallTimeLimitViolation,
        format!(
            "Wall time limit violated: used={} ms, limit={} ms",
            used_ms, limit_ms
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log process limit violation
pub fn process_limit_violation(correlation: CorrelationIds, count: u32, limit: u32) {
    let event = SecurityEvent::new(
        SecurityEventType::ProcessLimitViolation,
        format!("Process limit violated: count={}, limit={}", count, limit),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log output limit violation
pub fn output_limit_violation(correlation: CorrelationIds, size: u64, limit: u64) {
    let event = SecurityEvent::new(
        SecurityEventType::OutputLimitViolation,
        format!(
            "Output limit violated: size={} bytes, limit={} bytes",
            size, limit
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

// P2-AUDIT-001: Signal escalation event helpers

/// Log signal escalation event
pub fn signal_escalation(
    correlation: CorrelationIds,
    from_signal: String,
    to_signal: String,
    reason: String,
) {
    let event = SecurityEvent::new(
        SecurityEventType::SignalEscalation,
        format!(
            "Signal escalation: {} -> {} (reason: {})",
            from_signal, to_signal, reason
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log graceful kill event
pub fn graceful_kill(correlation: CorrelationIds, signal: String) {
    let event = SecurityEvent::new(
        SecurityEventType::GracefulKill,
        format!("Graceful kill initiated: signal={}", signal),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log forced kill event
pub fn forced_kill(correlation: CorrelationIds, reason: String) {
    let event = SecurityEvent::new(
        SecurityEventType::ForcedKill,
        format!("Forced kill: {}", reason),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

// P2-AUDIT-001: Cleanup event helpers

/// Log cleanup start event
pub fn cleanup_start(correlation: CorrelationIds) {
    let event = SecurityEvent::new(
        SecurityEventType::CleanupStart,
        format!("Cleanup started: run_id={}", correlation.run_id),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log cleanup success event
pub fn cleanup_success(correlation: CorrelationIds, details: String) {
    let event = SecurityEvent::new(
        SecurityEventType::CleanupSuccess,
        format!("Cleanup succeeded: {}", details),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log cleanup failure event
pub fn cleanup_failure(correlation: CorrelationIds, error: String) {
    let event = SecurityEvent::new(
        SecurityEventType::CleanupFailure,
        format!("Cleanup failed: {}", error),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

/// Log cleanup partial event
pub fn cleanup_partial(correlation: CorrelationIds, completed: Vec<String>, failed: Vec<String>) {
    let event = SecurityEvent::new(
        SecurityEventType::CleanupPartial,
        format!(
            "Cleanup partially succeeded: completed={:?}, failed={:?}",
            completed, failed
        ),
    )
    .with_correlation(correlation);

    log_security_event(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_ids_creation() {
        let correlation = CorrelationIds::new(42);
        assert_eq!(correlation.box_id, 42);
        assert!(correlation.root_pid.is_none());
        assert!(correlation.session_id.is_none());
        assert!(!correlation.request_id.is_empty());
        assert!(!correlation.run_id.is_empty());
    }

    #[test]
    fn test_correlation_ids_with_pid() {
        let correlation = CorrelationIds::new(42).with_root_pid(1234);
        assert_eq!(correlation.root_pid, Some(1234));
    }

    #[test]
    fn test_correlation_ids_with_session() {
        let correlation = CorrelationIds::new(42).with_session_id(5678);
        assert_eq!(correlation.session_id, Some(5678));
    }

    #[test]
    fn test_security_event_with_correlation() {
        let correlation = CorrelationIds::new(42);
        let event = SecurityEvent::new(
            SecurityEventType::ExecutionStart,
            "Test execution start".to_string(),
        )
        .with_correlation(correlation.clone());

        assert!(event.correlation.is_some());
        let event_correlation = event.correlation.unwrap();
        assert_eq!(event_correlation.box_id, 42);
    }

    #[test]
    fn test_security_event_with_envelope_id() {
        let event = SecurityEvent::new(
            SecurityEventType::ExecutionStart,
            "Test execution start".to_string(),
        )
        .with_envelope_id("test-envelope-id".to_string());

        assert_eq!(event.envelope_id, Some("test-envelope-id".to_string()));
    }

    #[test]
    fn test_event_type_severity() {
        assert!(matches!(
            SecurityEventType::ExecutionStart.default_severity(),
            SecuritySeverity::Low
        ));
        assert!(matches!(
            SecurityEventType::CleanupFailure.default_severity(),
            SecuritySeverity::Critical
        ));
        assert!(matches!(
            SecurityEventType::MemoryLimitViolation.default_severity(),
            SecuritySeverity::High
        ));
    }

    #[test]
    fn test_security_logger_creation() {
        let temp_dir = std::env::temp_dir();
        let audit_path = temp_dir.join("rustbox-test-audit.log");

        let logger = SecurityLogger::new(Some(audit_path.clone()));
        assert!(logger.is_ok());

        // Cleanup
        let _ = std::fs::remove_file(audit_path);
    }

    #[test]
    fn test_security_event_serialization() {
        let correlation = CorrelationIds::new(42);
        let event = SecurityEvent::new(
            SecurityEventType::ExecutionStart,
            "Test execution start".to_string(),
        )
        .with_correlation(correlation);

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
    }
}
