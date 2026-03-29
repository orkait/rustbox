use serde::{Deserialize, Serialize};
use std::time::SystemTime;

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

    #[serde(rename = "ple_cgroup_pids")]
    PleCgroupPids,

    #[serde(rename = "fse_limit_exceeded")]
    FseLimitExceeded,

    #[serde(rename = "ie_missing_evidence")]
    IeMissingEvidence,
    #[serde(rename = "ie_supervisor_failure")]
    IeSupervisorFailure,
    #[serde(rename = "ie_cleanup_failure")]
    IeCleanupFailure,

    #[serde(rename = "normal_exit")]
    NormalExit,
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
