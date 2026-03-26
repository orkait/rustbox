use crate::config::types::{IsolateConfig, IsolateError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageConfig {
    pub limits: LimitsConfig,
    #[serde(default)]
    pub compilation: Option<CompilationConfig>,
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub memory_mb: u64,
    #[serde(default)]
    pub virtual_memory_mb: Option<u64>,
    pub cpu_time_sec: u64,
    pub wall_time_sec: u64,
    pub max_processes: u32,
    #[serde(default = "default_max_file_size_kb")]
    pub max_file_size_kb: u64,
    #[serde(default = "default_max_open_files")]
    pub max_open_files: u32,
}

fn default_max_file_size_kb() -> u64 { 1024 }
fn default_max_open_files() -> u32 { 64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationConfig {
    pub command: Vec<String>,
    pub source_file: String,
    #[serde(default)]
    pub limits: Option<CompilationLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationLimits {
    #[serde(default = "default_compile_memory_mb")]
    pub memory_mb: u64,
    #[serde(default = "default_compile_max_processes")]
    pub max_processes: u32,
    #[serde(default = "default_compile_cpu_time_sec")]
    pub cpu_time_sec: u64,
    #[serde(default = "default_compile_wall_time_sec")]
    pub wall_time_sec: u64,
    #[serde(default)]
    pub fd_limit: Option<u64>,
    #[serde(default)]
    pub file_size_mb: Option<u64>,
}

pub fn default_compile_memory_mb() -> u64 { 256 }
pub fn default_compile_max_processes() -> u32 { 120 }
pub fn default_compile_cpu_time_sec() -> u64 { 15 }
pub fn default_compile_wall_time_sec() -> u64 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub command: Vec<String>,
    pub source_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBoxConfig {
    #[serde(default)]
    pub sandbox: SandboxConfig,
    pub languages: HashMap<String, LanguageConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "default_tmpfs_size_mb")]
    pub tmpfs_size_mb: u64,
}

fn default_tmpfs_size_mb() -> u64 { 256 }

impl Default for SandboxConfig {
    fn default() -> Self {
        Self { tmpfs_size_mb: default_tmpfs_size_mb() }
    }
}

impl RustBoxConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .map_err(|e| IsolateError::Config(format!("Failed to read config file: {}", e)))?;

        let config: RustBoxConfig = serde_json::from_str(&config_content)
            .map_err(|e| IsolateError::Config(format!("Failed to parse config JSON: {}", e)))?;

        Ok(config)
    }

    pub fn load_default() -> Result<Self> {
        let exe = std::env::current_exe().ok();
        let mut candidates = Vec::new();

        if let Some(ref exe_path) = exe {
            let mut dir = exe_path.parent();
            for _ in 0..5 {
                if let Some(d) = dir {
                    let candidate = d.join("config.json");
                    if candidate.exists() {
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if let Ok(meta) = std::fs::metadata(&candidate) {
                                let is_wsl_mount = candidate.to_string_lossy().starts_with("/mnt/");
                                if unsafe { libc::geteuid() } == 0
                                    && (meta.mode() & 0o002) != 0
                                    && !is_wsl_mount
                                {
                                    return Err(IsolateError::Config(format!(
                                        "REFUSED: config file {} is world-writable (mode {:o}). \
                                         Fix with: chmod 644 {}",
                                        candidate.display(),
                                        meta.mode() & 0o777,
                                        candidate.display()
                                    )));
                                }
                            }
                        }
                        candidates.push(candidate);
                        break;
                    }
                    dir = d.parent();
                }
            }
        }

        candidates.push(std::path::PathBuf::from("/etc/rustbox/config.json"));

        for path in &candidates {
            if path.exists() {
                return Self::load_from_file(path);
            }
        }

        Err(IsolateError::Config(
            "config.json not found (searched ./config.json and /etc/rustbox/config.json)"
                .to_string(),
        ))
    }

    pub fn get_language_config(&self, language: &str) -> Option<&LanguageConfig> {
        self.languages.get(&language.to_lowercase())
    }
}

impl IsolateConfig {
    pub fn with_language_defaults(language: &str, instance_id: String) -> Result<Self> {
        let mut config = Self {
            instance_id,
            ..Self::default()
        };

        if let Ok(rustbox_config) = RustBoxConfig::load_default() {
            if let Some(lang) = rustbox_config.get_language_config(language) {
                let l = &lang.limits;
                config.memory_limit = Some(l.memory_mb * 1024 * 1024);
                config.cpu_time_limit = Some(Duration::from_secs(l.cpu_time_sec));
                config.wall_time_limit = Some(Duration::from_secs(l.wall_time_sec));
                config.time_limit = Some(Duration::from_secs(l.cpu_time_sec));
                config.process_limit = Some(l.max_processes);
                config.file_size_limit = Some(l.max_file_size_kb * 1024);
                config.fd_limit = Some(l.max_open_files as u64);
                config.virtual_memory_limit = l.virtual_memory_mb
                    .map(|v| v * 1024 * 1024)
                    .or(Some(1024 * 1024 * 1024));
                config.tmpfs_size_bytes =
                    Some(rustbox_config.sandbox.tmpfs_size_mb * 1024 * 1024);

                for (key, value) in &lang.environment {
                    config.environment.push((key.clone(), value.clone()));
                }

                eprintln!("Loaded config.json defaults for {}:", language);
                eprintln!("  Memory: {} MB", l.memory_mb);
                eprintln!("  CPU time: {} sec", l.cpu_time_sec);
                eprintln!("  Wall time: {} sec", l.wall_time_sec);
                eprintln!("  Max processes: {}", l.max_processes);
            } else {
                eprintln!(
                    "Warning: Language '{}' not found in config.json, using defaults",
                    language
                );
            }
        } else {
            eprintln!("Warning: Could not load config.json, using hardcoded defaults");
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(lang: &str) -> IsolateConfig {
        IsolateConfig::with_language_defaults(lang, format!("test-{}", lang)).unwrap()
    }

    fn env_keys(config: &IsolateConfig) -> std::collections::HashSet<String> {
        config.environment.iter().map(|(k, _)| k.clone()).collect()
    }

    #[test]
    fn language_environments_loaded() {
        let java_env = env_keys(&load("java"));
        assert!(java_env.contains("JAVA_TOOL_OPTIONS"));
        assert!(java_env.contains("JAVA_HOME"));
        assert!(java_env.contains("CLASSPATH"));

        let py_env = env_keys(&load("python"));
        assert!(py_env.contains("PYTHONDONTWRITEBYTECODE"));
        assert!(py_env.contains("PYTHONUNBUFFERED"));
    }

    #[test]
    fn virtual_memory_limits_per_language() {
        assert_eq!(load("java").virtual_memory_limit, Some(4096 * 1024 * 1024));
        assert_eq!(load("python").virtual_memory_limit, Some(1024 * 1024 * 1024));
        assert_eq!(load("cpp").virtual_memory_limit, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn uid_gid_deferred_to_isolate() {
        let c = load("python");
        assert_eq!(c.uid, Some(65534));
        assert_eq!(c.gid, Some(65534));
    }

    #[test]
    fn compilation_config_loaded() {
        let config = RustBoxConfig::load_default().unwrap();
        let cpp = config.get_language_config("cpp").unwrap();
        assert!(cpp.compilation.is_some());
        let comp = cpp.compilation.as_ref().unwrap();
        assert!(comp.command[0].contains("g++"));
        assert_eq!(comp.source_file, "solution.cpp");

        let py = config.get_language_config("python").unwrap();
        assert!(py.compilation.is_none());
    }

    #[test]
    fn runtime_config_loaded() {
        let config = RustBoxConfig::load_default().unwrap();
        let py = config.get_language_config("python").unwrap();
        assert_eq!(py.runtime.command[0], "/usr/bin/python3");
        assert_eq!(py.runtime.source_file.as_deref(), Some("solution.py"));

        let cpp = config.get_language_config("cpp").unwrap();
        assert_eq!(cpp.runtime.command[0], "./solution");
        assert!(cpp.runtime.source_file.is_none());
    }
}
