use crate::config::types::{IsolateConfig, IsolateError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageConfig {
    pub memory: MemoryConfig,
    pub time: TimeConfig,
    pub processes: ProcessConfig,
    pub filesystem: FilesystemConfig,
    pub environment: HashMap<String, String>,
    pub compilation: CompilationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub limit_mb: u64,
    pub limit_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConfig {
    pub cpu_time_seconds: u64,
    pub wall_time_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub max_processes: u32,
    pub max_forks: Option<u32>,
    pub max_threads: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    pub max_file_size_kb: u64,
    pub max_open_files: u32,
    pub additional_read_only_paths: Vec<String>,
    pub required_binaries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationConfig {
    pub enabled: bool,
    pub compiler: String,
    pub compiler_args: Vec<String>,
    pub max_compilation_time: Option<u64>,
    pub max_compilation_memory_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBoxConfig {
    pub isolate: IsolateGlobalConfig,
    pub security: SecurityConfig,
    pub languages: HashMap<String, LanguageConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolateGlobalConfig {
    pub box_dir: String,
    pub run_dir: String,
    pub user: String,
    pub group: String,
    pub preserve_env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub drop_capabilities: bool,
    pub use_namespaces: bool,
    pub use_cgroups: bool,
    pub no_new_privileges: bool,
    pub chroot_jail: bool,
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
            if let Some(lang_config) = rustbox_config.get_language_config(language) {
                config.memory_limit = Some(lang_config.memory.limit_mb * 1024 * 1024);

                config.cpu_time_limit =
                    Some(Duration::from_secs(lang_config.time.cpu_time_seconds));
                config.wall_time_limit =
                    Some(Duration::from_secs(lang_config.time.wall_time_seconds));
                config.time_limit = Some(Duration::from_secs(lang_config.time.cpu_time_seconds));

                config.process_limit = Some(lang_config.processes.max_processes);

                config.file_size_limit = Some(lang_config.filesystem.max_file_size_kb * 1024);
                config.fd_limit = Some(lang_config.filesystem.max_open_files as u64);

                config.virtual_memory_limit = Some(match language.to_lowercase().as_str() {
                    "java" => 4 * 1024 * 1024 * 1024_u64,
                    "typescript" => 2 * 1024 * 1024 * 1024_u64,
                    "javascript" => 512 * 1024 * 1024_u64,
                    _ => 1024 * 1024 * 1024_u64,
                });

                for (key, value) in &lang_config.environment {
                    config.environment.push((key.clone(), value.clone()));
                }

                eprintln!("📋 Loaded config.json defaults for {}:", language);
                eprintln!("   Memory: {} MB", lang_config.memory.limit_mb);
                eprintln!("   CPU time: {} seconds", lang_config.time.cpu_time_seconds);
                eprintln!(
                    "   Wall time: {} seconds",
                    lang_config.time.wall_time_seconds
                );
                eprintln!("   Max processes: {}", lang_config.processes.max_processes);
            } else {
                eprintln!(
                    "⚠️  Warning: Language '{}' not found in config.json, using defaults",
                    language
                );
            }
        } else {
            eprintln!("⚠️  Warning: Could not load config.json, using hardcoded defaults");
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
        assert_eq!(
            load("java").virtual_memory_limit,
            Some(4 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            load("python").virtual_memory_limit,
            Some(1024 * 1024 * 1024)
        );
        assert_eq!(load("cpp").virtual_memory_limit, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn uid_gid_deferred_to_isolate() {
        let c = load("python");
        assert_eq!(c.uid, Some(65534));
        assert_eq!(c.gid, Some(65534));
    }
}
