mod common;

use rustbox::config::constants;
use rustbox::config::profile::SecurityProfile;
use rustbox::config::types::{ExecutionStatus, IsolateConfig};
use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

const PROFILE: SecurityProfile = SecurityProfile::Judge;
const STRICT: bool = false;

#[test]
#[ignore = "requires root + runtimes"]
fn seccomp_io_uring_enosys() {
    let code = r#"#include<iostream>
#include<cerrno>
#include<unistd.h>
#include<sys/syscall.h>
int main(){
    long ret=syscall(SYS_io_uring_setup,0,(void*)0);
    std::cout<<"errno="<<errno<<std::endl;
    return 0;
}"#;
    let result = common::run_code(PROFILE, "cpp", code, STRICT);
    assert_eq!(
        result.status,
        ExecutionStatus::Ok,
        "process must not be killed, seccomp should return ENOSYS"
    );
    let expected_errno = format!("errno={}", libc::ENOSYS);
    assert!(
        result.stdout.contains(&expected_errno),
        "stdout must contain '{}', got: {:?}",
        expected_errno,
        result.stdout
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn seccomp_ptrace_killed() {
    let code = "import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert!(
        matches!(
            result.status,
            ExecutionStatus::Signaled
                | ExecutionStatus::RuntimeError
                | ExecutionStatus::SecurityViolation
        ),
        "ptrace must be blocked by seccomp, got status: {:?}",
        result.status
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn seccomp_disabled_allows_execution() {
    common::init_subsystems();
    let config = common::load_config(PROFILE);
    let (lang, resolved) = common::resolve_for_language(PROFILE, &config, "python");

    let mut ic = IsolateConfig::from_language_config(
        &lang,
        &config.sandbox,
        &resolved,
        "test/seccomp-disabled".to_string(),
    );
    ic.strict_mode = STRICT;
    ic.no_seccomp = true;

    let mut isolate = Isolate::new(ic).expect("Isolate::new failed");
    let result = isolate
        .execute_code_string(
            "python",
            "print('hello')",
            &lang,
            &ExecutionOverrides::default(),
        )
        .expect("execute_code_string failed");
    let _ = isolate.cleanup();

    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "hello");
}

#[test]
#[ignore = "requires root + runtimes"]
fn no_new_privs_set_in_sandbox() {
    let code = r#"
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PR_GET_NO_NEW_PRIVS = 39
result = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
print(result)
"#;
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(
        result.stdout.trim(),
        "1",
        "PR_GET_NO_NEW_PRIVS must return 1 inside sandbox, got: {:?}",
        result.stdout.trim()
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn uid_dropped_in_sandbox() {
    let code = "import os; print(os.getuid())";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);

    let uid: u32 = result
        .stdout
        .trim()
        .parse()
        .expect("stdout must be a valid uid number");
    assert!(
        uid >= constants::DEFAULT_UID_POOL_BASE,
        "sandbox uid ({}) must be >= DEFAULT_UID_POOL_BASE ({})",
        uid,
        constants::DEFAULT_UID_POOL_BASE
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn capabilities_zeroed_in_sandbox() {
    let code = r#"
with open('/proc/self/status') as f:
    for line in f:
        for prefix in ['CapInh:', 'CapPrm:', 'CapEff:', 'CapBnd:', 'CapAmb:']:
            if line.startswith(prefix):
                print(line.strip())
"#;
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);

    for cap_line in &constants::REQUIRED_CAP_LINES {
        let found = result.stdout.lines().find(|l| l.starts_with(cap_line));
        let line = found.unwrap_or_else(|| panic!("stdout must contain '{}'", cap_line));
        let value = line
            .split_whitespace()
            .last()
            .expect("cap line must have a value");
        assert_eq!(
            value,
            constants::CAP_ZERO_HEX,
            "{} must be zeroed, got {}",
            cap_line,
            value
        );
    }
}

#[test]
#[ignore = "requires root + runtimes"]
fn sandbox_hostname_is_set() {
    let code = "import socket; print(socket.gethostname())";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.stdout.contains(constants::SANDBOX_HOSTNAME),
        "hostname must be '{}', got: {:?}",
        constants::SANDBOX_HOSTNAME,
        result.stdout.trim()
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn env_sanitized() {
    let code = r#"
import os
path = os.environ.get('PATH', '')
print('PATH=' + path)
print('LD_PRELOAD=' + os.environ.get('LD_PRELOAD', '<unset>'))
"#;
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);

    let path_line = result
        .stdout
        .lines()
        .find(|l| l.starts_with("PATH="))
        .expect("stdout must contain PATH= line");
    assert!(
        path_line.contains("/usr/bin"),
        "PATH must contain '/usr/bin' (part of SANDBOX_PATH), got: {:?}",
        path_line
    );

    let preload_line = result
        .stdout
        .lines()
        .find(|l| l.starts_with("LD_PRELOAD="))
        .expect("stdout must contain LD_PRELOAD= line");
    assert_eq!(
        preload_line, "LD_PRELOAD=<unset>",
        "LD_PRELOAD must not be set in sandbox, got: {:?}",
        preload_line
    );
}
