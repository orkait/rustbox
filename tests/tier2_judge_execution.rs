mod common;

use rustbox::config::profile::SecurityProfile;
use rustbox::config::types::ExecutionStatus;

const PROFILE: SecurityProfile = SecurityProfile::Judge;
const STRICT: bool = false;

#[test]
#[ignore = "requires root + runtimes"]
fn python_hello_world() {
    let result = common::run_code(PROFILE, "python", "print('hello world')", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "hello world");
    assert_eq!(result.exit_code, Some(0));
    assert!(
        result.wall_time > 0.0,
        "wall_time must be positive, got {}",
        result.wall_time
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn python_stdin_roundtrip() {
    let code = "print(input())";
    let result = common::run_code_with_stdin(PROFILE, "python", code, "rustbox\n", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.stdout.contains("rustbox"),
        "stdout must contain 'rustbox', got: {:?}",
        result.stdout
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn python_multiline_output() {
    let code = "for i in range(5): print(i)";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout, "0\n1\n2\n3\n4\n");
}

#[test]
#[ignore = "requires root + runtimes"]
fn python_exit_nonzero() {
    let code = "import sys; sys.exit(42)";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
    assert_eq!(
        result.exit_code,
        Some(42),
        "exit code must be 42, got {:?}",
        result.exit_code
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn python_syntax_error() {
    let code = "def f(\n  pass";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
    assert!(
        !result.stderr.is_empty(),
        "stderr must contain syntax error output"
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn python_runtime_exception() {
    let code = "raise ValueError('boom')";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
    assert!(
        result.stderr.contains("ValueError"),
        "stderr must contain 'ValueError', got: {:?}",
        result.stderr
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn cpp_compile_and_run() {
    let code = "#include<iostream>\nint main(){std::cout<<1024<<std::endl;}";
    let result = common::run_code(PROFILE, "cpp", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "1024");
}

#[test]
#[ignore = "requires root + runtimes"]
fn cpp_compile_error() {
    let code = "this is not valid c++";
    let result = common::run_code(PROFILE, "cpp", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
    assert!(
        !result.stderr.is_empty(),
        "stderr must contain compiler error output"
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn cpp_stdin_roundtrip() {
    let code = r#"#include<iostream>
#include<string>
int main(){std::string s;std::cin>>s;std::cout<<s;}"#;
    let result = common::run_code_with_stdin(PROFILE, "cpp", code, "rustbox\n", STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "rustbox");
}

#[test]
#[ignore = "requires root + runtimes"]
fn java_compile_and_run() {
    let code = "public class Main{public static void main(String[] a){System.out.println(1024);}}";
    let result = common::run_code(PROFILE, "java", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "1024");
}

#[test]
#[ignore = "requires root + runtimes"]
fn java_compile_error() {
    let code = "not valid java";
    let result = common::run_code(PROFILE, "java", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::RuntimeError);
}

#[test]
#[ignore = "requires root + runtimes"]
fn javascript_hello_world() {
    let code = r#"console.log("hello")"#;
    let result = common::run_code(PROFILE, "javascript", code, STRICT);
    assert_eq!(
        result.status,
        ExecutionStatus::Ok,
        "status={:?}, signal={:?}",
        result.status,
        result.signal
    );
    assert_eq!(result.stdout.trim(), "hello");
}

#[test]
#[ignore = "requires root + runtimes"]
fn typescript_hello_world() {
    let code = r#"console.log("hello")"#;
    let result = common::run_code(PROFILE, "typescript", code, STRICT);
    assert_eq!(
        result.status,
        ExecutionStatus::Ok,
        "status={:?}, signal={:?}",
        result.status,
        result.signal
    );
    assert_eq!(result.stdout.trim(), "hello");
}

#[test]
fn unsupported_language_not_in_config() {
    let config = common::load_config(SecurityProfile::Judge);
    assert!(
        config.get_language_config("brainfuck").is_none(),
        "brainfuck must not be present in judge config"
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn concurrent_execution_distinct_uids() {
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    common::init_subsystems();
    let thread_count = 5;
    let barrier = Arc::new(Barrier::new(thread_count));
    let results: Arc<Mutex<Vec<(ExecutionStatus, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for i in 0..thread_count {
        let barrier = barrier.clone();
        let results = results.clone();
        handles.push(thread::spawn(move || {
            let code = format!("import os; print(os.getuid())");
            barrier.wait();
            let result = common::run_code(PROFILE, "python", &code, STRICT);
            results
                .lock()
                .unwrap()
                .push((result.status, result.stdout.trim().to_string()));
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let results = results.lock().unwrap();
    assert_eq!(results.len(), thread_count);

    for (i, (status, _)) in results.iter().enumerate() {
        assert_eq!(*status, ExecutionStatus::Ok, "thread {} must succeed", i);
    }

    let uids: HashSet<&str> = results.iter().map(|(_, uid)| uid.as_str()).collect();
    assert_eq!(
        uids.len(),
        thread_count,
        "all {} sandboxes must get distinct UIDs, got: {:?}",
        thread_count,
        uids
    );
}
