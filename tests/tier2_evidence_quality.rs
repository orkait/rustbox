mod common;

use rustbox::config::constants;
use rustbox::config::profile::SecurityProfile;
use rustbox::config::types::{ExecutionStatus, OutputIntegrity};
use rustbox::runtime::isolate::ExecutionOverrides;

const PROFILE: SecurityProfile = SecurityProfile::Judge;
const STRICT: bool = false;

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_wall_time_nonzero() {
    let result = common::run_code(PROFILE, "python", "print(1)", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.wall_time > 0.0,
        "wall_time must be positive, got {}",
        result.wall_time
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_cpu_time_populated() {
    let result = common::run_code(PROFILE, "python", "print(1)", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.cpu_time >= 0.0,
        "cpu_time must be non-negative, got {}",
        result.cpu_time
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_memory_peak_nonzero() {
    let code = "x = list(range(10000))";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.memory_peak > 0,
        "memory_peak must be positive, got {}",
        result.memory_peak
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_exit_code_correct() {
    let result = common::run_code(PROFILE, "python", "print(1)", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(
        result.exit_code,
        Some(0),
        "successful execution must have exit_code=0, got {:?}",
        result.exit_code
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_stdout_complete() {
    let result = common::run_code(PROFILE, "python", "print('test')", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(
        result.output_integrity,
        OutputIntegrity::Complete,
        "small output must have Complete integrity, got {:?}",
        result.output_integrity
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_success_flag() {
    let result = common::run_code(PROFILE, "python", "print(1)", STRICT);
    assert!(result.success, "successful execution must set success=true");
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_re_has_stderr() {
    let code = "raise Exception('boom')";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
    assert!(
        result.stderr.contains("boom"),
        "stderr must contain 'boom', got: {:?}",
        result.stderr
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_signal_on_killed() {
    let code = "while True: pass";
    let overrides = ExecutionOverrides {
        max_cpu: Some(constants::TEST_SHORT_CPU_SECS),
        max_wall_time: Some(constants::TEST_SHORT_WALL_SECS),
        ..ExecutionOverrides::default()
    };
    let result = common::run_code_with_overrides(PROFILE, "python", code, STRICT, overrides);
    assert!(
        matches!(
            result.status,
            ExecutionStatus::TimeLimit | ExecutionStatus::Signaled
        ),
        "infinite loop must be killed, got: {:?}",
        result.status
    );
    let killed_by_signal = result.signal.is_some();
    let killed_by_status = result.status == ExecutionStatus::TimeLimit;
    assert!(
        killed_by_signal || killed_by_status,
        "must have either signal set or TLE status; signal={:?}, status={:?}",
        result.signal,
        result.status
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_bundle_has_cgroup_data() {
    let (_, evidence) = common::run_code_with_evidence(PROFILE, "python", "print(1)", true);
    let ev = evidence.expect("evidence must be present");
    let cg = ev
        .cgroup_evidence
        .expect("cgroup evidence must be present in strict mode");
    assert!(cg.memory_peak.unwrap_or(0) > 0, "memory_peak must be > 0");
    assert!(cg.memory_limit.unwrap_or(0) > 0, "memory_limit must be > 0");
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_bundle_has_applied_controls() {
    let (_, evidence) = common::run_code_with_evidence(PROFILE, "python", "print(1)", true);
    let ev = evidence.expect("evidence must be present");
    assert!(
        ev.applied_controls.contains(&"pid_namespace".to_string()),
        "applied_controls must include pid_namespace, got: {:?}",
        ev.applied_controls
    );
    assert!(
        ev.applied_controls
            .contains(&"no_new_privileges".to_string()),
        "applied_controls must include no_new_privileges, got: {:?}",
        ev.applied_controls
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_bundle_mode_is_strict() {
    let (_, evidence) = common::run_code_with_evidence(PROFILE, "python", "print(1)", true);
    let ev = evidence.expect("evidence must be present");
    assert_eq!(
        ev.resolve_mode(),
        rustbox::config::types::SecurityMode::Strict,
        "strict execution must produce strict mode evidence"
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn evidence_bundle_process_lifecycle_clean() {
    let (_, evidence) = common::run_code_with_evidence(PROFILE, "python", "print(1)", true);
    let ev = evidence.expect("evidence must be present");
    assert_eq!(
        ev.process_lifecycle.reap_summary, "clean",
        "clean execution must have 'clean' reap_summary, got: {:?}",
        ev.process_lifecycle.reap_summary
    );
}
