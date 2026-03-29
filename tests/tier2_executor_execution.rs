mod common;

use rustbox::config::profile::SecurityProfile;
use rustbox::config::types::ExecutionStatus;

const PROFILE: SecurityProfile = SecurityProfile::Executor;
const STRICT: bool = false;

#[test]
#[ignore = "requires root + runtimes"]
fn executor_python_numpy() {
    let code = "import numpy; print(numpy.array([1,2,3]).sum())";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert_eq!(result.stdout.trim(), "6");
}

#[test]
#[ignore = "requires root + runtimes"]
fn executor_python_pandas() {
    let code = "import pandas as pd; print(pd.DataFrame({'a':[1,2,3]}).sum().values[0])";
    let result = common::run_code(PROFILE, "python", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    let trimmed = result.stdout.trim();
    assert!(
        trimmed == "6" || trimmed == "6\n" || trimmed == "6.0",
        "stdout must be 6 (or 6.0), got: {:?}",
        trimmed
    );
}

#[test]
#[ignore = "requires root + runtimes"]
fn executor_cpp_nlohmann_json() {
    let code = r#"#include<iostream>
#include<nlohmann/json.hpp>
int main(){nlohmann::json j={{"key","value"}};std::cout<<j.dump()<<std::endl;}"#;
    let result = common::run_code(PROFILE, "cpp", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(!result.stdout.is_empty(), "stdout must contain JSON output");
}

#[test]
#[ignore = "requires root + runtimes"]
fn executor_java_threads() {
    let code = r#"public class Main{public static void main(String[] a) throws Exception{Thread.sleep(10);System.out.println("ok");}}"#;
    let result = common::run_code(PROFILE, "java", code, STRICT);
    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(
        result.stdout.contains("ok"),
        "stdout must contain 'ok', got: {:?}",
        result.stdout
    );
}
