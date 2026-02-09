/// Core types and structures for the rustbox system
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Directory binding configuration for filesystem access
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryBinding {
    /// Source directory on host system
    pub source: PathBuf,
    /// Target directory within sandbox
    pub target: PathBuf,
    /// Access permissions
    pub permissions: DirectoryPermissions,
    /// Ignore if source doesn't exist
    pub maybe: bool,
    /// Create as temporary directory
    pub is_tmp: bool,
}

/// Directory access permissions
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DirectoryPermissions {
    /// Read-only access
    ReadOnly,
    /// Read-write access
    ReadWrite,
    /// No execution allowed
    NoExec,
}

impl DirectoryBinding {
    /// Parse directory binding from string format like "source=target:options"
    pub fn parse(binding_str: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = binding_str.split(':').collect();
        let path_part = parts[0];
        let options = if parts.len() > 1 { parts[1] } else { "" };

        let (source, target) = if path_part.contains('=') {
            let path_parts: Vec<&str> = path_part.split('=').collect();
            if path_parts.len() != 2 {
                return Err(
                    "Invalid directory binding format. Use: source=target or source=target:options"
                        .to_string(),
                );
            }
            (PathBuf::from(path_parts[0]), PathBuf::from(path_parts[1]))
        } else {
            // If no target specified, use same path in sandbox
            (PathBuf::from(path_part), PathBuf::from(path_part))
        };

        let mut permissions = DirectoryPermissions::ReadOnly;
        let mut maybe = false;
        let mut is_tmp = false;

        for option in options.split(',') {
            match option.trim() {
                "rw" => permissions = DirectoryPermissions::ReadWrite,
                "ro" => permissions = DirectoryPermissions::ReadOnly,
                "noexec" => permissions = DirectoryPermissions::NoExec,
                "maybe" => maybe = true,
                "tmp" => is_tmp = true,
                "" => {} // Empty option
                _ => return Err(format!("Unknown directory binding option: {}", option)),
            }
        }

        Ok(DirectoryBinding {
            source,
            target,
            permissions,
            maybe,
            is_tmp,
        })
    }

    /// Parse directory binding with enhanced security validation
    pub fn parse_secure(binding_str: &str) -> crate::config::types::Result<Self> {
        use crate::observability::audit::events;
        use crate::runtime::security::path_validation;

        let parts: Vec<&str> = binding_str.split(':').collect();
        let path_part = parts[0];
        let options = if parts.len() > 1 { parts[1] } else { "" };

        let (source, target) = if path_part.contains('=') {
            let path_parts: Vec<&str> = path_part.split('=').collect();
            if path_parts.len() != 2 {
                return Err(crate::config::types::IsolateError::Config(
                    "Invalid directory binding format. Use: source=target or source=target:options"
                        .to_string(),
                ));
            }
            (
                std::path::Path::new(path_parts[0]),
                std::path::Path::new(path_parts[1]),
            )
        } else {
            // If no target specified, use same path in sandbox
            let path = std::path::Path::new(path_part);
            (path, path)
        };

        // Use security validation for paths
        let (validated_source, validated_target) =
            match path_validation::validate_directory_binding(source, target) {
                Ok(paths) => paths,
                Err(e) => {
                    // Log security event for path traversal attempt
                    events::path_traversal_attempt(binding_str.to_string(), None);
                    return Err(e);
                }
            };

        let mut permissions = DirectoryPermissions::ReadOnly;
        let mut maybe = false;
        let mut is_tmp = false;

        for option in options.split(',') {
            match option.trim() {
                "rw" => permissions = DirectoryPermissions::ReadWrite,
                "ro" => permissions = DirectoryPermissions::ReadOnly,
                "noexec" => permissions = DirectoryPermissions::NoExec,
                "maybe" => maybe = true,
                "tmp" => is_tmp = true,
                "" => {} // Empty option
                _ => {
                    return Err(crate::config::types::IsolateError::Config(format!(
                        "Unknown directory binding option: {}",
                        option
                    )))
                }
            }
        }

        Ok(DirectoryBinding {
            source: validated_source,
            target: validated_target,
            permissions,
            maybe,
            is_tmp,
        })
    }
}

/// Process isolation configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolateConfig {
    /// Unique identifier for this isolation instance
    pub instance_id: String,
    /// Working directory for the isolated process
    pub workdir: PathBuf,
    /// Root directory for chroot (optional)
    pub chroot_dir: Option<PathBuf>,
    /// User ID to run as
    pub uid: Option<u32>,
    /// Group ID to run as
    pub gid: Option<u32>,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// Time limit for execution
    pub time_limit: Option<Duration>,
    /// CPU time limit
    pub cpu_time_limit: Option<Duration>,
    /// Wall clock time limit
    pub wall_time_limit: Option<Duration>,
    /// Maximum number of processes
    pub process_limit: Option<u32>,
    /// Maximum file size
    pub file_size_limit: Option<u64>,
    /// Stack size limit in bytes
    pub stack_limit: Option<u64>,
    /// Core dump size limit in bytes (0 to disable core dumps)
    pub core_limit: Option<u64>,
    /// File descriptor limit (max open files)
    pub fd_limit: Option<u64>,
    /// Custom environment variables
    pub environment: Vec<(String, String)>,
    /// Strict mode: fail hard if cgroups unavailable or permission denied
    pub strict_mode: bool,
    /// Force cgroup v1 backend selection (`--cgroup-v1` override)
    #[serde(default)]
    pub force_cgroup_v1: bool,
    /// Inherit file descriptors from parent process
    #[serde(default)]
    pub inherit_fds: bool,
    /// Redirect stdout to file (optional)
    pub stdout_file: Option<PathBuf>,
    /// Redirect stderr to file (optional)
    pub stderr_file: Option<PathBuf>,
    /// Enable TTY support for interactive programs
    pub enable_tty: bool,
    /// Use pipes for real-time I/O instead of files
    pub use_pipes: bool,
    /// Input data to send to stdin
    pub stdin_data: Option<String>,
    /// Redirect stdin from file (optional)
    pub stdin_file: Option<PathBuf>,
    /// Buffer size for I/O operations (bytes)
    pub io_buffer_size: usize,
    /// Text encoding for I/O operations
    pub text_encoding: String,
    /// Namespace isolation configuration
    pub enable_pid_namespace: bool,
    pub enable_mount_namespace: bool,
    pub enable_network_namespace: bool,
    pub enable_user_namespace: bool,
    /// Allow degraded (no-isolation) fallback for non-root permissive mode.
    /// Default false: EPERM from clone() is a hard error unless explicitly opted in.
    #[serde(default)]
    pub allow_degraded: bool,
    /// Directory bindings for filesystem access
    pub directory_bindings: Vec<DirectoryBinding>,
}

impl IsolateConfig {
    /// Runtime root directory scoped by effective UID.
    /// Prevents root and non-root runs from colliding on shared `/tmp/rustbox`.
    pub fn runtime_root_dir() -> PathBuf {
        let euid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("rustbox-uid-{}", euid))
    }
}

impl Default for IsolateConfig {
    /// Judge-V1 default profile per plan.md Section 2.1
    /// - strict mode enabled
    /// - no network
    /// - single process limit
    /// - read-only filesystem with controlled writable work area
    /// - no_new_privileges required (enforced in executor)
    fn default() -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().to_string(),
            workdir: Self::runtime_root_dir(),
            chroot_dir: None,
            // Judge-v1 strict baseline: payload must drop to unprivileged identity.
            uid: Some(65534),                      // nobody
            gid: Some(65534),                      // nogroup
            memory_limit: Some(128 * 1024 * 1024), // 128MB default for judge
            time_limit: Some(Duration::from_secs(10)),
            cpu_time_limit: Some(Duration::from_secs(10)),
            wall_time_limit: Some(Duration::from_secs(20)),
            process_limit: Some(1), // Single process by default (judge-v1)
            file_size_limit: Some(64 * 1024 * 1024), // 64MB
            stack_limit: Some(8 * 1024 * 1024), // 8MB default stack
            core_limit: Some(0),    // Disable core dumps by default
            fd_limit: Some(64),     // Default file descriptor limit
            environment: Vec::new(),
            strict_mode: true, // Strict mode by default (judge-v1)
            force_cgroup_v1: false,
            inherit_fds: false,
            stdout_file: None,
            stderr_file: None,
            enable_tty: false,
            use_pipes: false,
            stdin_data: None,
            stdin_file: None,
            io_buffer_size: 8192, // 8KB default buffer
            text_encoding: "utf-8".to_string(),
            enable_pid_namespace: true,     // Mandatory for judge-v1
            enable_mount_namespace: true,   // Mandatory for judge-v1
            enable_network_namespace: true, // Network isolation
            enable_user_namespace: false,   // Rootful strict GA (judge-v1)
            allow_degraded: false,          // C3: Never degrade by default
            directory_bindings: Vec::new(),
        }
    }
}

/// Execution result from an isolated process
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Exit code of the process
    pub exit_code: Option<i32>,
    /// Execution status
    pub status: ExecutionStatus,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Output integrity state from runtime collector
    pub output_integrity: OutputIntegrity,
    /// CPU time used (in seconds)
    pub cpu_time: f64,
    /// Wall clock time used (in seconds)
    pub wall_time: f64,
    /// Peak memory usage (in bytes)
    pub memory_peak: u64,
    /// Signal that terminated the process (if any)
    pub signal: Option<i32>,
    /// Success flag
    pub success: bool,
    /// Additional error message
    pub error_message: Option<String>,
}

/// Status of process execution - STABLE TAXONOMY (v1 frozen)
/// Per plan.md Section 8.4: Status set is closed in v1
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    /// Process completed successfully (exit code 0, no violations)
    #[serde(rename = "OK")]
    Ok,
    /// Time limit exceeded (CPU or wall time)
    #[serde(rename = "TLE")]
    TimeLimit,
    /// Memory limit exceeded
    #[serde(rename = "MLE")]
    MemoryLimit,
    /// Runtime error (non-zero exit, non-limit signal)
    #[serde(rename = "RE")]
    RuntimeError,
    /// Internal error (judge infrastructure failure)
    #[serde(rename = "IE")]
    InternalError,
    /// Fatal signal (not attributable to judge kill or kernel limit)
    #[serde(rename = "SIG")]
    Signaled,
    /// Security violation (forbidden syscall, etc.)
    #[serde(rename = "SV")]
    SecurityViolation,
    /// Abuse pattern detected (fork bomb, FD exhaustion, etc.)
    #[serde(rename = "ABUSE")]
    Abuse,
    /// Process limit exceeded
    #[serde(rename = "PLE")]
    ProcessLimit,
    /// File size limit exceeded
    #[serde(rename = "FSE")]
    FileSizeLimit,
}

/// Verdict actor - who made the termination decision
/// Per plan.md Section 8.4: Closed set in v1
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum VerdictActor {
    /// Judge system initiated termination
    #[serde(rename = "judge")]
    Judge,
    /// Kernel enforced limit
    #[serde(rename = "kernel")]
    Kernel,
    /// Runtime/program behavior
    #[serde(rename = "runtime")]
    Runtime,
}

/// Verdict cause - specific reason for non-OK verdict
/// Per plan.md Section 8.4: Closed set in v1
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum VerdictCause {
    // TLE causes
    #[serde(rename = "tle_cpu_judge")]
    TleCpuJudge,
    #[serde(rename = "tle_cpu_kernel")]
    TleCpuKernel,
    #[serde(rename = "tle_wall_judge")]
    TleWallJudge,

    // MLE causes
    #[serde(rename = "mle_kernel_oom")]
    MleKernelOom,
    #[serde(rename = "mle_limit_breach")]
    MleLimitBreach,

    // RE causes
    #[serde(rename = "re_nonzero_exit")]
    ReNonzeroExit,
    #[serde(rename = "re_fatal_signal")]
    ReFatalSignal,

    // SIG causes
    #[serde(rename = "sig_unattributed")]
    SigUnattributed,

    // ABUSE causes
    #[serde(rename = "abuse_fork_bomb")]
    AbuseForkBomb,
    #[serde(rename = "abuse_fd_exhaustion")]
    AbuseFdExhaustion,
    #[serde(rename = "abuse_signal_storm")]
    AbuseSignalStorm,
    #[serde(rename = "abuse_exec_churn")]
    AbuseExecChurn,

    // IE causes
    #[serde(rename = "ie_missing_evidence")]
    IeMissingEvidence,
    #[serde(rename = "ie_contradictory_evidence")]
    IeContradictoryEvidence,
    #[serde(rename = "ie_supervisor_failure")]
    IeSupervisorFailure,
    #[serde(rename = "ie_cleanup_failure")]
    IeCleanupFailure,

    // Other
    #[serde(rename = "normal_exit")]
    NormalExit,
}

/// Output integrity classification
/// Per plan.md Section 12
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OutputIntegrity {
    #[serde(rename = "complete")]
    Complete,
    #[serde(rename = "truncated_by_judge_limit")]
    TruncatedByJudgeLimit,
    #[serde(rename = "truncated_by_program_close")]
    TruncatedByProgramClose,
    #[serde(rename = "crash_mid_write")]
    CrashMidWrite,
    #[serde(rename = "write_error")]
    WriteError,
}

impl std::fmt::Display for OutputIntegrity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputIntegrity::Complete => write!(f, "complete"),
            OutputIntegrity::TruncatedByJudgeLimit => write!(f, "truncated_by_judge_limit"),
            OutputIntegrity::TruncatedByProgramClose => write!(f, "truncated_by_program_close"),
            OutputIntegrity::CrashMidWrite => write!(f, "crash_mid_write"),
            OutputIntegrity::WriteError => write!(f, "write_error"),
        }
    }
}

impl Default for OutputIntegrity {
    fn default() -> Self {
        OutputIntegrity::Complete
    }
}

/// CPU vs Wall divergence classification
/// Per plan.md Section 13
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DivergenceClass {
    #[serde(rename = "cpu_bound")]
    CpuBound,
    #[serde(rename = "sleep_or_block_bound")]
    SleepOrBlockBound,
    #[serde(rename = "host_interference_suspected")]
    HostInterferenceSuspected,
}

/// Custom error types for rustbox
#[derive(Error, Debug)]
pub enum IsolateError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("Lock error: {0}")]
    Lock(String),

    #[error("Lock already held by process")]
    LockBusy,

    #[error("Lock file corrupted or incompatible")]
    LockCorrupted,

    #[error("Namespace isolation error: {0}")]
    Namespace(String),

    #[error("Resource limit error: {0}")]
    ResourceLimit(String),

    #[error("Filesystem error: {0}")]
    Filesystem(String),

    #[error("Privilege error: {0}")]
    Privilege(String),

    #[error("Advanced lock error: {0}")]
    AdvancedLock(LockError),
}

/// Enhanced lock error types for the new locking system
#[derive(Error, Debug)]
pub enum LockError {
    #[error("Box {box_id} is busy (owned by PID {owner_pid:?})")]
    Busy { box_id: u32, owner_pid: Option<u32> },

    #[error(
        "Timeout waiting for box {box_id} after {waited:?} (current owner: {current_owner:?})"
    )]
    Timeout {
        box_id: u32,
        waited: Duration,
        current_owner: Option<String>,
    },

    #[error("Lock directory permission denied: {details}")]
    PermissionDenied { details: String },

    #[error("Filesystem error: {0}")]
    FilesystemError(#[from] std::io::Error),

    #[error("Lock corruption detected for box {box_id}: {details}")]
    CorruptedLock { box_id: u32, details: String },

    #[error("System error: {message}")]
    SystemError { message: String },

    #[error("Lock manager not initialized")]
    NotInitialized,
}

/// Convert lock errors to appropriate exit codes
impl From<LockError> for i32 {
    fn from(err: LockError) -> i32 {
        match err {
            LockError::Busy { .. } => 2,              // Temporary failure
            LockError::Timeout { .. } => 3,           // Timeout
            LockError::PermissionDenied { .. } => 77, // Permission error
            LockError::FilesystemError(_) => 74,      // IO error
            LockError::CorruptedLock { .. } => 75,    // Data error
            LockError::SystemError { .. } => 1,       // General error
            LockError::NotInitialized => 1,           // General error
        }
    }
}

/// Result type for lock operations
pub type LockResult<T> = std::result::Result<T, LockError>;

/// Lock information stored in lock files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub pid: u32,
    pub box_id: u32,
    pub created_at: SystemTime,
    pub rustbox_version: String,
}

/// Health status for lock manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Lock manager health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockManagerHealth {
    pub status: HealthStatus,
    pub active_locks: u32,
    pub stale_locks_cleaned: u64,
    pub lock_directory_writable: bool,
    pub cleanup_thread_alive: bool,
    pub metrics: LockMetrics,
}

/// Metrics for lock operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockMetrics {
    pub total_acquisitions: u64,
    pub average_acquisition_time_ms: f64,
    pub lock_contentions: u64,
    pub cleanup_operations: u64,
    pub stale_locks_cleaned: u64,
    pub errors_by_type: HashMap<String, u64>,
}

/// Result type alias for rustbox operations
pub type Result<T> = std::result::Result<T, IsolateError>;
impl From<std::process::Output> for ExecutionResult {
    fn from(output: std::process::Output) -> Self {
        let status = if output.status.success() {
            ExecutionStatus::Ok
        } else {
            ExecutionStatus::RuntimeError
        };

        Self {
            exit_code: output.status.code(),
            status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            output_integrity: OutputIntegrity::Complete,
            cpu_time: 0.0,  // Not available from std::process::Output
            wall_time: 0.0, // Not available from std::process::Output
            memory_peak: 0, // Not available from std::process::Output
            signal: {
                use std::os::unix::process::ExitStatusExt;
                output.status.signal()
            },
            success: output.status.success(),
            error_message: None,
        }
    }
}
impl From<nix::errno::Errno> for IsolateError {
    fn from(err: nix::errno::Errno) -> Self {
        IsolateError::Process(err.to_string())
    }
}
impl Default for ExecutionStatus {
    fn default() -> Self {
        ExecutionStatus::Ok
    }
}

/// Capability Report - Per plan.md Section 4.2
/// Reports what controls were configured, applied, and missing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Controls that were requested/configured
    pub configured_controls: Vec<String>,
    /// Controls that were successfully applied
    pub applied_controls: Vec<String>,
    /// Controls that could not be applied
    pub missing_controls: Vec<String>,
    /// Execution mode
    pub mode: SecurityMode,
    /// Reason for mode decision
    pub mode_decision_reason: String,
    /// Reason execution is unsafe (if applicable)
    pub unsafe_execution_reason: Option<String>,
    /// Selected cgroup backend
    pub cgroup_backend_selected: Option<String>,
    /// pidfd support mode
    pub pidfd_mode: PidfdMode,
    /// /proc policy applied
    pub proc_policy_applied: String,
    /// /sys policy applied
    pub sys_policy_applied: String,
}

/// Security mode
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SecurityMode {
    /// Strict: mandatory controls must be enforced
    #[serde(rename = "strict")]
    Strict,
    /// Permissive: degraded controls allowed but marked unsafe
    #[serde(rename = "permissive")]
    Permissive,
    /// Dev: trusted local debugging, no sandbox guarantees
    #[serde(rename = "dev")]
    Dev,
}

/// pidfd support mode
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PidfdMode {
    #[serde(rename = "native")]
    Native,
    #[serde(rename = "fallback")]
    Fallback,
    #[serde(rename = "unavailable")]
    Unavailable,
}

/// Evidence Bundle - Per plan.md Section 8.5.1
/// Immutable evidence collected during execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Wait outcome (exit code, signal, etc.)
    pub wait_outcome: WaitOutcome,
    /// Judge actions (timer expiries, signals sent, escalation)
    pub judge_actions: Vec<JudgeAction>,
    /// Cgroup evidence snapshot
    pub cgroup_evidence: Option<CgroupEvidence>,
    /// Timing evidence
    pub timing_evidence: TimingEvidence,
    /// Process lifecycle evidence
    pub process_lifecycle: ProcessLifecycleEvidence,
    /// Evidence collection errors
    pub evidence_collection_errors: Vec<String>,
}

/// Wait outcome from process termination
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitOutcome {
    /// Exit code (if normal exit)
    pub exit_code: Option<i32>,
    /// Terminating signal (if signaled)
    pub terminating_signal: Option<i32>,
    /// Whether process was stopped
    pub stopped: bool,
    /// Whether process was continued
    pub continued: bool,
}

/// Judge action during execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeAction {
    /// Timestamp of action
    pub timestamp: SystemTime,
    /// Action type
    pub action_type: JudgeActionType,
    /// Action details
    pub details: String,
}

/// Judge action types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JudgeActionType {
    #[serde(rename = "timer_expiry")]
    TimerExpiry,
    #[serde(rename = "signal_sent")]
    SignalSent,
    #[serde(rename = "escalation")]
    Escalation,
    #[serde(rename = "forced_kill")]
    ForcedKill,
}

/// Cgroup evidence from resource accounting
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CgroupEvidence {
    /// Memory usage peak
    pub memory_peak: Option<u64>,
    /// Memory limit
    pub memory_limit: Option<u64>,
    /// OOM events
    pub oom_events: u64,
    /// OOM kill events
    pub oom_kill_events: u64,
    /// CPU usage (microseconds)
    pub cpu_usage_usec: Option<u64>,
    /// Process count
    pub process_count: Option<u32>,
    /// Process limit
    pub process_limit: Option<u32>,
}

/// Timing evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingEvidence {
    /// Wall clock elapsed (monotonic)
    pub wall_elapsed_ms: u64,
    /// CPU time used (from cgroup or rusage)
    pub cpu_time_ms: u64,
    /// CPU/wall ratio
    pub cpu_wall_ratio: f64,
    /// Divergence classification
    pub divergence_class: Option<DivergenceClass>,
}

/// Process lifecycle evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessLifecycleEvidence {
    /// Reap summary
    pub reap_summary: String,
    /// Descendant containment summary
    pub descendant_containment: String,
    /// Zombie count after cleanup
    pub zombie_count: u32,
}

/// Verdict Provenance - Per plan.md Section 8.5
/// Complete provenance for non-OK verdicts
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerdictProvenance {
    /// Who made the termination decision
    pub verdict_actor: VerdictActor,
    /// Specific reason for verdict
    pub verdict_cause: VerdictCause,
    /// Evidence sources used
    pub verdict_evidence_sources: Vec<String>,
    /// Terminating signal (if applicable)
    pub termination_signal: Option<i32>,
    /// CPU time used
    pub cpu_time_used: f64,
    /// Wall time used
    pub wall_time_used: f64,
    /// Peak memory usage
    pub memory_peak: u64,
    /// Limit snapshot at execution time
    pub limit_snapshot: LimitSnapshot,
    /// Evidence collection errors
    pub evidence_collection_errors: Vec<String>,
}

/// Limit snapshot at execution time
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitSnapshot {
    pub cpu_limit_ms: Option<u64>,
    pub wall_limit_ms: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub process_limit: Option<u32>,
    pub output_limit_bytes: Option<u64>,
}

/// Enhanced Execution Result with Judge-V1 requirements
/// Per plan.md Section 14.1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeExecutionResult {
    /// Execution status (stable taxonomy)
    pub status: ExecutionStatus,
    /// Exit code (if normal exit)
    pub exit_code: Option<i32>,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Output integrity classification
    pub output_integrity: OutputIntegrity,
    /// CPU time used (seconds)
    pub cpu_time: f64,
    /// Wall time used (seconds)
    pub wall_time: f64,
    /// Peak memory usage (bytes)
    pub memory_peak: u64,
    /// Verdict provenance (for non-OK)
    pub verdict_provenance: Option<VerdictProvenance>,
    /// Capability report
    pub capability_report: CapabilityReport,
    /// Execution envelope ID (SHA256 hash)
    pub execution_envelope_id: String,
    /// Evidence bundle
    pub evidence_bundle: EvidenceBundle,
    /// Language runtime envelope (if applicable)
    pub language_runtime_envelope: Option<String>,
}

/// Execution Envelope Inputs - Per plan.md Section 14.2
/// Canonical inputs for deterministic envelope hash
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEnvelopeInputs {
    /// Kernel release
    pub kernel_release: String,
    /// Key capability flags
    pub capability_flags: Vec<String>,
    /// Namespace set actually applied
    pub namespaces_applied: Vec<String>,
    /// Cgroup backend
    pub cgroup_backend: String,
    /// Effective limit set
    pub effective_limits: LimitSnapshot,
    /// Mount topology fingerprint
    pub mount_topology_fingerprint: String,
    /// UID/GID execution identity
    pub uid_gid_identity: String,
    /// Rustbox version/build
    pub rustbox_version: String,
    /// Language runtime envelope ID
    pub language_runtime_envelope_id: Option<String>,
}

impl ExecutionEnvelopeInputs {
    /// Compute SHA256 hash of canonical envelope inputs
    pub fn compute_envelope_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
