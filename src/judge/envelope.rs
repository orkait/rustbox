use anyhow::Result;

use crate::config::types::{CapabilityReport, ExecutionResult, ExecutionStatus, IsolateConfig};
use crate::sandbox::types::LaunchEvidence;

fn build_envelope_id(
    config: &IsolateConfig,
    capability_report: &CapabilityReport,
    language_runtime_envelope: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    hasher.update(format!("rustbox-{}", env!("CARGO_PKG_VERSION")));
    hasher.update(format!(
        "uid:{}",
        config
            .uid
            .unwrap_or_else(|| unsafe { libc::geteuid() as u32 })
    ));
    hasher.update(format!(
        "gid:{}",
        config
            .gid
            .unwrap_or_else(|| unsafe { libc::getegid() as u32 })
    ));

    if let Some(mem) = config.memory_limit {
        hasher.update(format!("mem:{}", mem));
    }
    if let Some(cpu) = config.cpu_time_limit {
        hasher.update(format!("cpu:{}", cpu.as_millis()));
    }
    if let Some(wall) = config.wall_time_limit {
        hasher.update(format!("wall:{}", wall.as_millis()));
    }
    if let Some(procs) = config.process_limit {
        hasher.update(format!("procs:{}", procs));
    }

    if let Some(backend) = &capability_report.cgroup_backend_selected {
        hasher.update(format!("cgroup:{}", backend));
    }

    if let Some(lang) = language_runtime_envelope {
        hasher.update(format!("lang:{}", lang));
    }

    format!("{:x}", hasher.finalize())
}

pub fn emit_judge_json(
    result: &ExecutionResult,
    config: &IsolateConfig,
    language_runtime_envelope: Option<&str>,
    launch_evidence: Option<&LaunchEvidence>,
) -> Result<ExecutionStatus> {
    let evidence = launch_evidence.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing runtime launch evidence; refusing to emit static capability claims"
        )
    })?;
    let capability_report = evidence.to_capability_report();
    let envelope_id = build_envelope_id(config, &capability_report, language_runtime_envelope);
    let judge_result = crate::verdict::json_schema::JudgeResultV1::from_execution_result(
        result,
        config,
        evidence,
        capability_report,
        envelope_id,
        language_runtime_envelope.map(|s| s.to_string()),
    );

    println!("{}", judge_result.to_json()?);
    Ok(judge_result.status)
}
