mod common;

use rustbox::config::constants;
use rustbox::config::profile::SecurityProfile;
use rustbox::config::types::{ExecutionStatus, OutputIntegrity};
use rustbox::runtime::isolate::ExecutionOverrides;

const PROFILE: SecurityProfile = SecurityProfile::Judge;
const STRICT: bool = false;

#[test]
#[ignore = "requires root + runtimes"]
fn tle_cpu_infinite_loop() {
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
        "infinite CPU loop must trigger TLE or Signaled, got: {:?}",
        result.status
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn tle_wall_sleep() {
    let code = "import time; time.sleep(999)";
    let overrides = ExecutionOverrides {
        max_wall_time: Some(constants::TEST_SHORT_WALL_SECS),
        ..ExecutionOverrides::default()
    };
    let result = common::run_code_with_overrides(PROFILE, "python", code, STRICT, overrides);
    assert!(
        matches!(
            result.status,
            ExecutionStatus::TimeLimit | ExecutionStatus::Signaled | ExecutionStatus::InternalError
        ),
        "long sleep must be killed (TLE/Signaled/IE if safety timeout fires first), got: {:?}",
        result.status
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn mle_large_allocation() {
    let code = "x = [0] * 100_000_000";
    let memory_limit_mb: u64 = 32;
    let overrides = ExecutionOverrides {
        max_memory: Some(memory_limit_mb),
        ..ExecutionOverrides::default()
    };
    let result = common::run_code_with_overrides(PROFILE, "python", code, STRICT, overrides);
    assert!(
        matches!(
            result.status,
            ExecutionStatus::MemoryLimit
                | ExecutionStatus::Signaled
                | ExecutionStatus::RuntimeError
        ),
        "large allocation with {}MB limit must fail, got: {:?}",
        memory_limit_mb,
        result.status
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn output_truncation() {
    let code = "print('x' * 20_000_000)";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_ne!(
        result.output_integrity,
        OutputIntegrity::Complete,
        "20MB of output must be truncated, got integrity: {:?}",
        result.output_integrity
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn process_limit_fork() {
    let code = r#"
import os, time
pids = []
for _ in range(50):
    pid = os.fork()
    if pid == 0:
        time.sleep(60)
        os._exit(0)
    pids.append(pid)
"#;
    let overrides = ExecutionOverrides {
        process_limit: Some(constants::DEFAULT_PROCESS_LIMIT),
        ..ExecutionOverrides::default()
    };
    let result = common::run_code_with_overrides(PROFILE, "python", code, STRICT, overrides);
    assert_ne!(
        result.status,
        ExecutionStatus::Ok,
        "fork bomb with children alive must not succeed"
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn file_size_limit() {
    let code = r#"
with open('/tmp/sandbox/bigfile', 'wb') as f:
    f.write(b'\x00' * (128 * 1024 * 1024))
"#;
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert!(
        matches!(
            result.status,
            ExecutionStatus::FileSizeLimit | ExecutionStatus::RuntimeError
        ),
        "writing beyond file size limit must fail, got: {:?}",
        result.status
    );
}
