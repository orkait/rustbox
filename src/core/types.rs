use crate::config::types::{
    CapabilityReport, CgroupEvidence, DirectoryBinding, ExecutionResult, JudgeAction,
    OutputIntegrity, PidfdMode, ProcessLifecycleEvidence, SecurityMode, SyscallFilterSource,
};
use crate::config::types::{ExecutionStatus, IsolateConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Runtime execution profile consumed by sandbox core.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProfile {
    pub command: Vec<String>,
    pub stdin_data: Option<String>,
    pub environment: Vec<(String, String)>,
    pub inherit_fds: bool,
    pub workdir: PathBuf,
    pub chroot_dir: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub strict_mode: bool,
    pub enable_pid_namespace: bool,
    pub enable_mount_namespace: bool,
    pub enable_network_namespace: bool,
    pub enable_user_namespace: bool,
    pub enable_syscall_filtering: bool,
    pub memory_limit: Option<u64>,
    pub file_size_limit: Option<u64>,
    pub stack_limit: Option<u64>,
    pub core_limit: Option<u64>,
    pub process_limit: Option<u32>,
    pub cpu_time_limit_ms: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub fd_limit: Option<u64>,
    pub directory_bindings: Vec<DirectoryBinding>,
}

impl ExecutionProfile {
    pub fn from_config(
        config: &IsolateConfig,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Self {
        Self {
            command: command.to_vec(),
            stdin_data: stdin_data.map(str::to_string),
            environment: config.environment.clone(),
            inherit_fds: config.inherit_fds,
            workdir: config.workdir.clone(),
            chroot_dir: config.chroot_dir.clone(),
            uid: config.uid,
            gid: config.gid,
            strict_mode: config.strict_mode,
            enable_pid_namespace: config.enable_pid_namespace,
            enable_mount_namespace: config.enable_mount_namespace,
            enable_network_namespace: config.enable_network_namespace,
            enable_user_namespace: config.enable_user_namespace,
            enable_syscall_filtering: config.enable_syscall_filtering,
            memory_limit: config.memory_limit,
            file_size_limit: config.file_size_limit,
            stack_limit: config.stack_limit,
            core_limit: config.core_limit,
            process_limit: config.process_limit,
            cpu_time_limit_ms: config.cpu_time_limit.map(|d| d.as_millis() as u64),
            wall_time_limit_ms: config.wall_time_limit.map(|d| d.as_millis() as u64),
            fd_limit: config.fd_limit,
            directory_bindings: config.directory_bindings.clone(),
        }
    }
}

/// Optional workspace metadata used by judge adapters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunWorkspace {
    pub root: PathBuf,
    pub workdir: PathBuf,
    pub temp_dir: PathBuf,
}

/// Host->proxy launch contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxLaunchRequest {
    pub instance_id: String,
    pub profile: ExecutionProfile,
    pub cgroup_attach_path: Option<PathBuf>,
}

impl SandboxLaunchRequest {
    pub fn from_config(
        config: &IsolateConfig,
        command: &[String],
        stdin_data: Option<&str>,
        cgroup_attach_path: Option<PathBuf>,
    ) -> Self {
        Self {
            instance_id: config.instance_id.clone(),
            profile: ExecutionProfile::from_config(config, command, stdin_data),
            cgroup_attach_path,
        }
    }
}

/// Signal escalation report for timeout/forced termination paths.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KillReport {
    pub term_sent: bool,
    pub kill_sent: bool,
    pub waited_ms: u64,
    pub notes: Vec<String>,
}

/// Runtime evidence produced by core.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaunchEvidence {
    pub strict_requested: bool,
    pub running_as_root: bool,
    pub configured_controls: Vec<String>,
    pub applied_controls: Vec<String>,
    pub missing_controls: Vec<String>,
    pub mode_decision_reason: String,
    pub unsafe_execution_reason: Option<String>,
    pub cgroup_backend_selected: Option<String>,
    pub pidfd_mode: PidfdMode,
    pub proc_policy_applied: String,
    pub sys_policy_applied: String,
    pub syscall_filtering_enabled: bool,
    pub syscall_filtering_source: SyscallFilterSource,
    pub syscall_filtering_profile_id: Option<String>,
    pub judge_actions: Vec<JudgeAction>,
    pub cgroup_evidence: Option<CgroupEvidence>,
    pub process_lifecycle: ProcessLifecycleEvidence,
    pub evidence_collection_errors: Vec<String>,
    pub cleanup_verified: bool,
}

impl LaunchEvidence {
    pub fn resolve_mode(&self) -> SecurityMode {
        if self.strict_requested && self.missing_controls.is_empty() {
            return SecurityMode::Strict;
        }
        if self.running_as_root {
            SecurityMode::Permissive
        } else {
            SecurityMode::Dev
        }
    }

    pub fn to_capability_report(&self) -> CapabilityReport {
        CapabilityReport {
            configured_controls: self.configured_controls.clone(),
            applied_controls: self.applied_controls.clone(),
            missing_controls: self.missing_controls.clone(),
            mode: self.resolve_mode(),
            mode_decision_reason: self.mode_decision_reason.clone(),
            unsafe_execution_reason: self.unsafe_execution_reason.clone(),
            cgroup_backend_selected: self.cgroup_backend_selected.clone(),
            pidfd_mode: self.pidfd_mode.clone(),
            proc_policy_applied: self.proc_policy_applied.clone(),
            sys_policy_applied: self.sys_policy_applied.clone(),
            syscall_filtering_enabled: self.syscall_filtering_enabled,
            syscall_filtering_source: self.syscall_filtering_source.clone(),
            syscall_filtering_profile_id: self.syscall_filtering_profile_id.clone(),
        }
    }
}

/// Proxy->host status payload transferred through status pipe.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub payload_pid: Option<i32>,
    pub exit_code: Option<i32>,
    pub term_signal: Option<i32>,
    pub timed_out: bool,
    pub wall_time_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub output_integrity: OutputIntegrity,
    pub internal_error: Option<String>,
    pub reaped_descendants: u32,
}

impl ProxyStatus {
    pub fn to_execution_result(&self) -> ExecutionResult {
        let status = if self.internal_error.is_some() {
            ExecutionStatus::InternalError
        } else if self.timed_out {
            ExecutionStatus::TimeLimit
        } else if self.term_signal.is_some() {
            ExecutionStatus::Signaled
        } else if self.exit_code == Some(0) {
            ExecutionStatus::Ok
        } else {
            ExecutionStatus::RuntimeError
        };

        ExecutionResult {
            exit_code: self.exit_code,
            status: status.clone(),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            output_integrity: self.output_integrity.clone(),
            cpu_time: 0.0,
            wall_time: self.wall_time_ms as f64 / 1000.0,
            memory_peak: 0,
            signal: self.term_signal,
            success: status == ExecutionStatus::Ok,
            error_message: self.internal_error.clone(),
        }
    }
}

/// Core launch output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxLaunchOutcome {
    pub proxy_host_pid: i32,
    pub payload_host_pid: Option<i32>,
    pub result: ExecutionResult,
    pub evidence: LaunchEvidence,
    pub kill_report: Option<KillReport>,
    pub proxy_status: ProxyStatus,
}
