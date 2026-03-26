use serde::{Deserialize, Serialize};

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

impl OutputIntegrity {
    pub fn resolve_combined(stdout: &Self, stderr: &Self) -> Self {
        if matches!(stdout, Self::WriteError) || matches!(stderr, Self::WriteError) {
            Self::WriteError
        } else if matches!(stdout, Self::CrashMidWrite) || matches!(stderr, Self::CrashMidWrite) {
            Self::CrashMidWrite
        } else if matches!(stdout, Self::TruncatedByJudgeLimit)
            || matches!(stderr, Self::TruncatedByJudgeLimit)
        {
            Self::TruncatedByJudgeLimit
        } else if matches!(stdout, Self::TruncatedByProgramClose)
            || matches!(stderr, Self::TruncatedByProgramClose)
        {
            Self::TruncatedByProgramClose
        } else {
            Self::Complete
        }
    }
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
