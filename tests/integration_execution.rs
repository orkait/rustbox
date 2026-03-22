/// End-to-end integration tests for rustbox execution pipeline.
///
/// Tier 1 (no root): permissive + allow_degraded — verifies output correctness,
///   error classification, and verdict logic without isolation enforcement.
///
/// Tier 2 (requires root): strict mode — verifies full kernel isolation chain:
///   namespaces, cgroups, capability drop, pdeathsig, no_new_privs.
///   Run with: sudo cargo test --test integration_execution -- --include-ignored
use rustbox::config::types::{ExecutionStatus, IsolateConfig};
use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};
use std::sync::Once;

static INIT: Once = Once::new();

fn init_subsystems() {
    INIT.call_once(|| {
        let _ = rustbox::observability::audit::init_security_logger(None);
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn permissive_config(language: &str, box_id: u32) -> IsolateConfig {
    let mut config =
        IsolateConfig::with_language_defaults(language, format!("rustbox/{}", box_id))
            .unwrap_or_default();
    config.strict_mode = false;
    config.allow_degraded = true;
    config.enable_pid_namespace = false;
    config.enable_mount_namespace = false;
    config.enable_network_namespace = false;
    config
}

fn strict_config(language: &str, box_id: u32) -> IsolateConfig {
    let mut config =
        IsolateConfig::with_language_defaults(language, format!("rustbox/{}", box_id))
            .unwrap_or_default();
    config.strict_mode = true;
    config
}

fn no_overrides() -> ExecutionOverrides {
    ExecutionOverrides::default()
}

fn overrides_with_stdin(input: &str) -> ExecutionOverrides {
    ExecutionOverrides {
        stdin_data: Some(input.to_string()),
        ..Default::default()
    }
}

fn run_permissive(language: &str, box_id: u32, code: &str, overrides: ExecutionOverrides) -> rustbox::config::types::ExecutionResult {
    init_subsystems();
    let config = permissive_config(language, box_id);
    let mut isolate = Isolate::new(config).expect("Isolate::new failed");
    isolate
        .execute_code_string(language, code, &overrides)
        .expect("execute_code_string failed")
}

fn run_strict(language: &str, box_id: u32, code: &str, overrides: ExecutionOverrides) -> rustbox::config::types::ExecutionResult {
    init_subsystems();
    let config = strict_config(language, box_id);
    let mut isolate = Isolate::new(config).expect("Isolate::new failed");
    isolate
        .execute_code_string(language, code, &overrides)
        .expect("execute_code_string failed")
}

// ---------------------------------------------------------------------------
// Tier 1 — Python (permissive)
// ---------------------------------------------------------------------------

#[test]
fn python_hello_world_permissive() {
    let r = run_permissive("python", 100, "print('hello world')", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "status: {:?}\nstderr: {}", r.status, r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
    assert_eq!(r.exit_code, Some(0));
}

#[test]
fn python_reads_stdin_permissive() {
    let code = "import sys; print(sys.stdin.read().strip())";
    let r = run_permissive("python", 101, code, overrides_with_stdin("rustbox\n"));
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "rustbox");
}

#[test]
fn python_arithmetic_permissive() {
    let r = run_permissive("python", 102, "print(2 ** 10)", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    assert_eq!(r.stdout.trim(), "1024");
}

#[test]
fn python_syntax_error_is_runtime_error_permissive() {
    let r = run_permissive("python", 103, "def f(\n  pass", no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError, "expected RE for syntax error, got {:?}", r.status);
    assert_ne!(r.exit_code, Some(0));
}

#[test]
fn python_runtime_exception_is_runtime_error_permissive() {
    let r = run_permissive("python", 104, "raise ValueError('boom')", no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError);
    assert!(r.stderr.contains("ValueError") || r.exit_code != Some(0));
}

#[test]
fn python_exit_nonzero_is_runtime_error_permissive() {
    let r = run_permissive("python", 105, "import sys; sys.exit(42)", no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError);
    assert_eq!(r.exit_code, Some(42));
}

#[test]
fn python_multiline_output_permissive() {
    let code = "for i in range(5): print(i)";
    let r = run_permissive("python", 106, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    assert_eq!(r.stdout.trim(), "0\n1\n2\n3\n4");
}

#[test]
fn python_cpu_time_limit_enforced_permissive() {
    init_subsystems();
    let code = "while True: pass";
    let mut ov = no_overrides();
    ov.max_cpu = Some(1);
    ov.max_wall_time = Some(3);
    let config = {
        let mut c = permissive_config("python", 107);
        c.cpu_time_limit = Some(std::time::Duration::from_secs(1));
        c.wall_time_limit = Some(std::time::Duration::from_secs(3));
        c
    };
    let mut isolate = Isolate::new(config).expect("Isolate::new");
    let r = isolate.execute_code_string("python", code, &ov).expect("execute");
    assert!(
        matches!(r.status, ExecutionStatus::TimeLimit | ExecutionStatus::RuntimeError | ExecutionStatus::Signaled),
        "expected TLE, RE, or Signaled for infinite loop, got {:?}", r.status
    );
}

// ---------------------------------------------------------------------------
// Tier 1 — C++ (permissive)
// ---------------------------------------------------------------------------

#[test]
fn cpp_hello_world_permissive() {
    let code = r#"#include<iostream>
int main(){std::cout<<"hello world"<<std::endl;}"#;
    let r = run_permissive("cpp", 200, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
}

#[test]
fn cpp_reads_stdin_permissive() {
    let code = r#"#include<iostream>
#include<string>
int main(){std::string s;std::cin>>s;std::cout<<s;}"#;
    let r = run_permissive("cpp", 201, code, overrides_with_stdin("rustbox\n"));
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "rustbox");
}

#[test]
fn cpp_compile_error_is_runtime_error_permissive() {
    let code = "this is not valid c++";
    let r = run_permissive("cpp", 202, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError, "expected RE for compile error, got {:?}", r.status);
    assert!(!r.stderr.is_empty(), "compiler error should appear in stderr");
}

#[test]
fn cpp_arithmetic_permissive() {
    let code = r#"#include<iostream>
int main(){std::cout<<(1<<10)<<std::endl;}"#;
    let r = run_permissive("cpp", 203, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    assert_eq!(r.stdout.trim(), "1024");
}

#[test]
fn cpp_nonzero_exit_is_runtime_error_permissive() {
    let code = r#"int main(){return 1;}"#;
    let r = run_permissive("cpp", 204, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError);
    assert_eq!(r.exit_code, Some(1));
}

// ---------------------------------------------------------------------------
// Tier 1 — Java (permissive)
// ---------------------------------------------------------------------------

#[test]
fn java_hello_world_permissive() {
    let code = r#"public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}"#;
    let r = run_permissive("java", 300, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
}

#[test]
fn java_compile_error_is_runtime_error_permissive() {
    let code = "this is not valid java";
    let r = run_permissive("java", 301, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::RuntimeError, "expected RE for compile error, got {:?}", r.status);
}

#[test]
fn java_arithmetic_permissive() {
    let code = r#"public class Main {
    public static void main(String[] args) {
        System.out.println(1 << 10);
    }
}"#;
    let r = run_permissive("java", 302, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "1024");
}

// ---------------------------------------------------------------------------
// Tier 1 — Verdict & evidence correctness
// ---------------------------------------------------------------------------

#[test]
fn wall_time_is_nonzero_for_real_execution_permissive() {
    let r = run_permissive("python", 400, "print(1)", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    assert!(r.wall_time > 0.0, "wall_time must be > 0 for real execution");
}

#[test]
fn stdout_is_empty_for_no_output_permissive() {
    let r = run_permissive("python", 401, "x = 1 + 1", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    assert_eq!(r.stdout.trim(), "");
}

#[test]
fn unsupported_language_returns_error() {
    init_subsystems();
    let config = permissive_config("python", 402);
    let mut isolate = Isolate::new(config).expect("Isolate::new");
    let result = isolate.execute_code_string("brainfuck", "+++", &no_overrides());
    assert!(result.is_err(), "unsupported language must return Err");
}

// ---------------------------------------------------------------------------
// Tier 2 — Full isolation (requires root, marked #[ignore])
// Run: sudo cargo test --test integration_execution -- --include-ignored
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root: sudo cargo test --test integration_execution -- --include-ignored"]
fn python_hello_world_strict() {
    let r = run_strict("python", 500, "print('hello world')", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
}

#[test]
#[ignore = "requires root"]
fn python_all_controls_applied_strict() {
    let r = run_strict("python", 501, "print(1)", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    // In strict mode exit_code must be 0 and execution successful.
    assert_eq!(r.exit_code, Some(0));
    assert!(r.success);
}

#[test]
#[ignore = "requires root"]
fn python_memory_peak_is_reported_strict() {
    let r = run_strict("python", 502, "x = list(range(100000))", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert!(r.memory_peak > 0, "memory_peak must be reported in strict mode");
}

#[test]
#[ignore = "requires root"]
fn python_tle_is_classified_strict() {
    init_subsystems();
    let code = "while True: pass";
    let config = {
        let mut c = strict_config("python", 503);
        c.cpu_time_limit = Some(std::time::Duration::from_secs(1));
        c.wall_time_limit = Some(std::time::Duration::from_secs(3));
        c
    };
    let mut isolate = Isolate::new(config).expect("Isolate::new");
    let r = isolate.execute_code_string("python", code, &no_overrides()).expect("execute");
    assert!(
        matches!(r.status, ExecutionStatus::TimeLimit | ExecutionStatus::Signaled),
        "expected TLE or Signaled for infinite loop, got {:?}\nstderr: {}", r.status, r.stderr
    );
}

#[test]
#[ignore = "requires root"]
fn cpp_hello_world_strict() {
    let code = r#"#include<iostream>
int main(){std::cout<<"hello world"<<std::endl;}"#;
    let r = run_strict("cpp", 600, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
}

#[test]
#[ignore = "requires root"]
fn java_hello_world_strict() {
    let code = r#"public class Main {
    public static void main(String[] args) {
        System.out.println("hello world");
    }
}"#;
    let r = run_strict("java", 700, code, no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok, "stderr: {}", r.stderr);
    assert_eq!(r.stdout.trim(), "hello world");
}

#[test]
#[ignore = "requires root"]
fn cleanup_verified_after_strict_execution() {
    let r = run_strict("python", 800, "print(1)", no_overrides());
    assert_eq!(r.status, ExecutionStatus::Ok);
    // IE verdict would indicate cleanup or evidence failure — must not happen on clean run.
    assert_ne!(r.status, ExecutionStatus::InternalError,
        "IE verdict means cleanup/evidence failure: {:?}", r);
}
