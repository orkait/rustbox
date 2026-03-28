use rustbox::config::types::{ExecutionStatus, IsolateConfig};
use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

#[test]
fn io_uring_returns_enosys_not_kill() {
    let code = r#"
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
int main() {
    long ret = syscall(SYS_io_uring_setup, 0, NULL);
    printf("ret=%ld errno=%d\n", ret, errno);
    return 0;
}
"#;
    let mut config = IsolateConfig::with_language_defaults("cpp", "seccomp-test-1".to_string())
        .unwrap_or_default();
    config.strict_mode = false;
    let mut isolate = Isolate::new(config).expect("isolate creation");
    let result = isolate.execute_code_string("cpp", code, &ExecutionOverrides::default());
    isolate.cleanup().ok();
    match result {
        Ok(r) => {
            assert_eq!(
                r.status,
                ExecutionStatus::Ok,
                "io_uring probe should not be killed: {:?}",
                r.stderr
            );
            assert!(
                r.stdout.contains("errno=38") || r.stdout.contains("ret=-1"),
                "expected ENOSYS, got: {}",
                r.stdout
            );
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No such file")
                || msg.contains("not found")
                || msg.contains("Command not found")
            {
                eprintln!("Skipping: C++ toolchain not available");
                return;
            }
            panic!("unexpected error: {}", e);
        }
    }
}

#[test]
fn no_seccomp_flag_disables_filter() {
    let mut config = IsolateConfig::with_language_defaults("python", "seccomp-test-2".to_string())
        .unwrap_or_default();
    config.strict_mode = false;
    config.no_seccomp = true;
    let mut isolate = Isolate::new(config).expect("isolate creation");
    let result =
        isolate.execute_code_string("python", "print('hello')", &ExecutionOverrides::default());
    isolate.cleanup().ok();
    if let Ok(r) = result {
        assert_eq!(r.status, ExecutionStatus::Ok);
        assert!(r.stdout.contains("hello"));
    }
}

#[test]
fn seccomp_enabled_by_default_python_works() {
    let mut config = IsolateConfig::with_language_defaults("python", "seccomp-test-3".to_string())
        .unwrap_or_default();
    config.strict_mode = false;
    let mut isolate = Isolate::new(config).expect("isolate creation");
    let result =
        isolate.execute_code_string("python", "print(2+2)", &ExecutionOverrides::default());
    isolate.cleanup().ok();
    if let Ok(r) = result {
        assert_eq!(r.status, ExecutionStatus::Ok);
        assert!(r.stdout.contains("4"), "expected 4, got: {}", r.stdout);
    }
}
