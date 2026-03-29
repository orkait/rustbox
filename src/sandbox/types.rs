use crate::config::types::{
    CapabilityReport, CgroupEvidence, DirectoryBinding, ExecutionResult, JudgeAction,
    OutputIntegrity, PidfdMode, ProcessLifecycleEvidence, SecurityMode,
};
use crate::config::types::{ExecutionStatus, IsolateConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub memory_limit: Option<u64>,
    pub file_size_limit: Option<u64>,
    pub stack_limit: Option<u64>,
    pub core_limit: Option<u64>,
    pub process_limit: Option<u32>,
    pub cpu_time_limit_ms: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub fd_limit: Option<u64>,
    pub virtual_memory_limit: Option<u64>,
    pub directory_bindings: Vec<DirectoryBinding>,
    pub enable_seccomp: bool,
    pub seccomp_policy_file: Option<std::path::PathBuf>,
    pub tmpfs_size_bytes: Option<u64>,
    pub pipe_buffer_size: Option<u64>,
    pub output_limit: Option<u64>,
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
            memory_limit: config.memory_limit,
            file_size_limit: config.file_size_limit,
            stack_limit: config.stack_limit,
            core_limit: config.core_limit,
            process_limit: config.process_limit,
            cpu_time_limit_ms: config.cpu_time_limit.map(|d| d.as_millis() as u64),
            wall_time_limit_ms: config.wall_time_limit.map(|d| d.as_millis() as u64),
            fd_limit: config.fd_limit,
            virtual_memory_limit: config.virtual_memory_limit,
            directory_bindings: config.directory_bindings.clone(),
            enable_seccomp: !config.no_seccomp,
            seccomp_policy_file: config.seccomp_policy_file.clone(),
            tmpfs_size_bytes: config.tmpfs_size_bytes,
            pipe_buffer_size: config.pipe_buffer_size,
            output_limit: config.output_limit,
        }
    }
}

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KillReport {
    pub term_sent: bool,
    pub kill_sent: bool,
    pub waited_ms: u64,
    pub notes: Vec<String>,
}

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
        }
    }
}

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
        let interrupted_signal = self.internal_error.as_deref().and_then(|msg| {
            msg.strip_prefix("interrupted_by_signal:")
                .and_then(|s| s.parse::<i32>().ok())
        });
        let resolved_signal = self.term_signal.or(interrupted_signal);

        let is_rlimit_cpu = matches!(resolved_signal, Some(libc::SIGXCPU));

        let status = if self.timed_out || is_rlimit_cpu {
            ExecutionStatus::TimeLimit
        } else if resolved_signal.is_some() {
            ExecutionStatus::Signaled
        } else if self.internal_error.is_some() {
            ExecutionStatus::InternalError
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
            wall_time: self.wall_time_ms as f64 / crate::config::constants::MS_PER_SEC_F64,
            memory_peak: 0,
            signal: resolved_signal,
            success: status == ExecutionStatus::Ok,
            error_message: self.internal_error.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxLaunchOutcome {
    pub result: ExecutionResult,
    pub evidence: LaunchEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_internal_error_maps_to_signaled_status() {
        let status = ProxyStatus {
            internal_error: Some("interrupted_by_signal:15".to_string()),
            ..ProxyStatus::default()
        };

        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::Signaled);
        assert_eq!(result.signal, Some(15));
    }

    #[test]
    fn timeout_still_takes_precedence_over_signal() {
        let status = ProxyStatus {
            timed_out: true,
            term_signal: Some(libc::SIGTERM),
            internal_error: Some("interrupted_by_signal:15".to_string()),
            ..ProxyStatus::default()
        };

        let result = status.to_execution_result();
        assert_eq!(result.status, ExecutionStatus::TimeLimit);
    }
}
