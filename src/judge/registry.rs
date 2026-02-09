use crate::config::types::{IsolateError, Result};
use crate::judge::adapter::JudgeAdapter;
use crate::judge::languages::{cpp::CppAdapter, java::JavaAdapter, python::PythonAdapter};

pub fn adapter_for(language: &str) -> Result<Box<dyn JudgeAdapter>> {
    match language {
        "python" | "py" => Ok(Box::new(PythonAdapter)),
        "cpp" | "c++" | "cxx" | "cc" | "c" => Ok(Box::new(CppAdapter)),
        "java" => Ok(Box::new(JavaAdapter)),
        _ => Err(IsolateError::Config(format!(
            "unsupported language adapter: {language}"
        ))),
    }
}
