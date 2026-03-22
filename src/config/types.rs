use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryBinding {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permissions: DirectoryPermissions,
    pub maybe: bool,
    pub is_tmp: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DirectoryPermissions {
    ReadOnly,
    ReadWrite,
    NoExec,
}

impl DirectoryBinding {
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
            let path = std::path::Path::new(path_part);
            (path, path)
        };

        let (validated_source, validated_target) =
            match path_validation::validate_directory_binding(source, target) {
                Ok(paths) => paths,
                Err(e) => {
                    events::path_traversal_attempt(binding_str, None);
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
                "" => {}
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolateConfig {
    pub instance_id: String,
    pub workdir: PathBuf,
    pub chroot_dir: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub memory_limit: Option<u64>,
    pub time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub wall_time_limit: Option<Duration>,
    pub process_limit: Option<u32>,
    pub file_size_limit: Option<u64>,
    pub stack_limit: Option<u64>,
    pub core_limit: Option<u64>,
    pub fd_limit: Option<u64>,
    pub virtual_memory_limit: Option<u64>,
    #[serde(skip_serializing, default)]
    pub environment: Vec<(String, String)>,
    pub strict_mode: bool,
    #[serde(default)]
    pub force_cgroup_v1: bool,
    #[serde(default)]
    pub inherit_fds: bool,
    pub stdout_file: Option<PathBuf>,
    pub stderr_file: Option<PathBuf>,
    pub enable_tty: bool,
    pub use_pipes: bool,
    pub stdin_data: Option<String>,
    pub stdin_file: Option<PathBuf>,
    pub io_buffer_size: usize,
    pub text_encoding: String,
    pub enable_pid_namespace: bool,
    pub enable_mount_namespace: bool,
    pub enable_network_namespace: bool,
    pub enable_user_namespace: bool,
    #[serde(default)]
    pub allow_degraded: bool,
    #[serde(default)]
    pub no_seccomp: bool,
    #[serde(default)]
    pub seccomp_policy_file: Option<PathBuf>,
    pub directory_bindings: Vec<DirectoryBinding>,
}

impl IsolateConfig {
    pub fn runtime_root_dir() -> PathBuf {
        let euid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("rustbox-uid-{}", euid))
    }

}

impl Default for IsolateConfig {
    fn default() -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().to_string(),
            workdir: Self::runtime_root_dir(),
            chroot_dir: None,
            uid: Some(65534),
            gid: Some(65534),
            memory_limit: Some(128 * 1024 * 1024),
            time_limit: Some(Duration::from_secs(10)),
            cpu_time_limit: Some(Duration::from_secs(10)),
            wall_time_limit: Some(Duration::from_secs(20)),
            process_limit: Some(10),
            file_size_limit: Some(64 * 1024 * 1024),
            stack_limit: Some(8 * 1024 * 1024),
            core_limit: Some(0),
            fd_limit: Some(64),
            virtual_memory_limit: None,
            environment: Vec::new(),
            strict_mode: true,
            force_cgroup_v1: false,
            inherit_fds: false,
            stdout_file: None,
            stderr_file: None,
            enable_tty: false,
            use_pipes: false,
            stdin_data: None,
            stdin_file: None,
            io_buffer_size: 8192,
            text_encoding: "utf-8".to_string(),
            enable_pid_namespace: true,
            enable_mount_namespace: true,
            enable_network_namespace: true,
            enable_user_namespace: false,
            allow_degraded: false,
            no_seccomp: false,
            seccomp_policy_file: None,
            directory_bindings: Vec::new(),
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub status: ExecutionStatus,
    pub stdout: String,
    pub stderr: String,
    pub output_integrity: OutputIntegrity,
    pub cpu_time: f64,
    pub wall_time: f64,
    pub memory_peak: u64,
    pub signal: Option<i32>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    #[default]
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "TLE")]
    TimeLimit,
    #[serde(rename = "MLE")]
    MemoryLimit,
    #[serde(rename = "RE")]
    RuntimeError,
    #[serde(rename = "IE")]
    InternalError,
    #[serde(rename = "SIG")]
    Signaled,
    #[serde(rename = "SV")]
    SecurityViolation,
    #[serde(rename = "ABUSE")]
    Abuse,
    #[serde(rename = "PLE")]
    ProcessLimit,
    #[serde(rename = "FSE")]
    FileSizeLimit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum VerdictActor {
    #[serde(rename = "judge")]
    Judge,
    #[serde(rename = "kernel")]
    Kernel,
    #[serde(rename = "runtime")]
    Runtime,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum VerdictCause {
    #[serde(rename = "tle_cpu_judge")]
    TleCpuJudge,
    #[serde(rename = "tle_cpu_kernel")]
    TleCpuKernel,
    #[serde(rename = "tle_wall_judge")]
    TleWallJudge,

    #[serde(rename = "mle_kernel_oom")]
    MleKernelOom,
    #[serde(rename = "mle_limit_breach")]
    MleLimitBreach,

    #[serde(rename = "re_nonzero_exit")]
    ReNonzeroExit,
    #[serde(rename = "re_fatal_signal")]
    ReFatalSignal,

    #[serde(rename = "sig_unattributed")]
    SigUnattributed,

    #[serde(rename = "abuse_fork_bomb")]
    AbuseForkBomb,
    #[serde(rename = "abuse_fd_exhaustion")]
    AbuseFdExhaustion,
    #[serde(rename = "abuse_signal_storm")]
    AbuseSignalStorm,
    #[serde(rename = "abuse_exec_churn")]
    AbuseExecChurn,

    #[serde(rename = "ie_missing_evidence")]
    IeMissingEvidence,
    #[serde(rename = "ie_contradictory_evidence")]
    IeContradictoryEvidence,
    #[serde(rename = "ie_supervisor_failure")]
    IeSupervisorFailure,
    #[serde(rename = "ie_cleanup_failure")]
    IeCleanupFailure,

    #[serde(rename = "normal_exit")]
    NormalExit,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum OutputIntegrity {
    #[default]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DivergenceClass {
    #[serde(rename = "cpu_bound")]
    CpuBound,
    #[serde(rename = "sleep_or_block_bound")]
    SleepOrBlockBound,
    #[serde(rename = "host_interference_suspected")]
    HostInterferenceSuspected,
}

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

    #[error("Namespace isolation error: {0}")]
    Namespace(String),

    #[error("Resource limit error: {0}")]
    ResourceLimit(String),

    #[error("Filesystem error: {0}")]
    Filesystem(String),

    #[error("Privilege error: {0}")]
    Privilege(String),

}

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
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            output_integrity: OutputIntegrity::Complete,
            cpu_time: 0.0,
            wall_time: 0.0,
            memory_peak: 0,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub configured_controls: Vec<String>,
    pub applied_controls: Vec<String>,
    pub missing_controls: Vec<String>,
    pub mode: SecurityMode,
    pub mode_decision_reason: String,
    pub unsafe_execution_reason: Option<String>,
    pub cgroup_backend_selected: Option<String>,
    pub pidfd_mode: PidfdMode,
    pub proc_policy_applied: String,
    pub sys_policy_applied: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SecurityMode {
    #[serde(rename = "strict")]
    Strict,
    #[serde(rename = "permissive")]
    Permissive,
    #[serde(rename = "dev")]
    Dev,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PidfdMode {
    #[serde(rename = "native")]
    Native,
    #[serde(rename = "fallback")]
    Fallback,
    #[serde(rename = "unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub wait_outcome: WaitOutcome,
    pub judge_actions: Vec<JudgeAction>,
    pub cgroup_evidence: Option<CgroupEvidence>,
    pub timing_evidence: TimingEvidence,
    pub process_lifecycle: ProcessLifecycleEvidence,
    pub evidence_collection_errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitOutcome {
    pub exit_code: Option<i32>,
    pub terminating_signal: Option<i32>,
    pub stopped: bool,
    pub continued: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeAction {
    pub timestamp: SystemTime,
    pub action_type: JudgeActionType,
    pub details: String,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CgroupEvidence {
    pub memory_peak: Option<u64>,
    pub memory_limit: Option<u64>,
    pub oom_events: u64,
    pub oom_kill_events: u64,
    pub cpu_usage_usec: Option<u64>,
    pub process_count: Option<u32>,
    pub process_limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingEvidence {
    pub wall_elapsed_ms: u64,
    pub cpu_time_ms: u64,
    pub cpu_wall_ratio: f64,
    pub divergence_class: Option<DivergenceClass>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessLifecycleEvidence {
    pub reap_summary: String,
    pub descendant_containment: String,
    pub zombie_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerdictProvenance {
    pub verdict_actor: VerdictActor,
    pub verdict_cause: VerdictCause,
    pub verdict_evidence_sources: Vec<String>,
    pub termination_signal: Option<i32>,
    pub cpu_time_used: f64,
    pub wall_time_used: f64,
    pub memory_peak: u64,
    pub limit_snapshot: LimitSnapshot,
    pub evidence_collection_errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitSnapshot {
    pub cpu_limit_ms: Option<u64>,
    pub wall_limit_ms: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub process_limit: Option<u32>,
    pub output_limit_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JudgeExecutionResult {
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_integrity: OutputIntegrity,
    pub cpu_time: f64,
    pub wall_time: f64,
    pub memory_peak: u64,
    pub verdict_provenance: Option<VerdictProvenance>,
    pub capability_report: CapabilityReport,
    pub execution_envelope_id: String,
    pub evidence_bundle: EvidenceBundle,
    pub language_runtime_envelope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEnvelopeInputs {
    pub kernel_release: String,
    pub capability_flags: Vec<String>,
    pub namespaces_applied: Vec<String>,
    pub cgroup_backend: String,
    pub effective_limits: LimitSnapshot,
    pub mount_topology_fingerprint: String,
    pub uid_gid_identity: String,
    pub rustbox_version: String,
    pub language_runtime_envelope_id: Option<String>,
}

impl ExecutionEnvelopeInputs {
    pub fn compute_envelope_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
