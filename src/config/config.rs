use crate::config::types::{IsolateConfig, IsolateError, Result};
/// Configuration loading from config.json
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Language-specific configuration from config.json
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

/// Full config.json structure
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
    /// Load configuration from config.json file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .map_err(|e| IsolateError::Config(format!("Failed to read config file: {}", e)))?;

        let config: RustBoxConfig = serde_json::from_str(&config_content)
            .map_err(|e| IsolateError::Config(format!("Failed to parse config JSON: {}", e)))?;

        Ok(config)
    }

    /// Load configuration from the project root.
    /// Binaries:     `<root>/target/{debug,release}/<name>`      → 3 levels up
    /// Test binaries: `<root>/target/{debug,release}/deps/<name>` → 4 levels up
    /// Fallback: /etc/rustbox/config.json (Docker/production).
    pub fn load_default() -> Result<Self> {
        let exe = std::env::current_exe().ok();
        let mut candidates = Vec::new();

        // Walk up from exe directory, checking each level for config.json
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
                                // In strict/root context, reject world-writable config
                                // Skip check on WSL mounts (/mnt/) where everything is 0777
                                let is_wsl_mount = candidate.to_string_lossy().starts_with("/mnt/");
                                if unsafe { libc::geteuid() } == 0
                                    && (meta.mode() & 0o002) != 0
                                    && !is_wsl_mount
                                {
                                    log::warn!(
                                        "Skipping world-writable config file: {}",
                                        candidate.display()
                                    );
                                    continue;
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

    /// Get language-specific configuration
    pub fn get_language_config(&self, language: &str) -> Option<&LanguageConfig> {
        self.languages.get(&language.to_lowercase())
    }
}

impl IsolateConfig {
    /// Create IsolateConfig with language-specific defaults from config.json
    pub fn with_language_defaults(language: &str, instance_id: String) -> Result<Self> {
        let mut config = Self {
            instance_id,
            ..Self::default()
        };

        // Derive per-box UID/GID from instance_id (IOI Isolate convention: 60000 + box_id).
        if let Some(box_id_str) = config.instance_id.strip_prefix("rustbox/") {
            if let Ok(box_id) = box_id_str.parse::<u32>() {
                let uid = Self::uid_for_box(box_id);
                config.uid = Some(uid);
                config.gid = Some(uid);
            }
        }

        // Try to load config.json and apply language-specific settings
        if let Ok(rustbox_config) = RustBoxConfig::load_default() {
            if let Some(lang_config) = rustbox_config.get_language_config(language) {
                // Apply memory limits
                config.memory_limit = Some(lang_config.memory.limit_mb * 1024 * 1024);

                // Apply time limits - this is the key fix!
                config.cpu_time_limit =
                    Some(Duration::from_secs(lang_config.time.cpu_time_seconds));
                config.wall_time_limit =
                    Some(Duration::from_secs(lang_config.time.wall_time_seconds));
                config.time_limit = Some(Duration::from_secs(lang_config.time.cpu_time_seconds));

                // Apply process limits
                config.process_limit = Some(lang_config.processes.max_processes);

                // Apply file system limits
                config.file_size_limit = Some(lang_config.filesystem.max_file_size_kb * 1024);
                config.fd_limit = Some(lang_config.filesystem.max_open_files as u64);

                // Per-language virtual address space limit (RLIMIT_AS).
                // Java 17+ needs >=4GB for compressed class pointers.
                config.virtual_memory_limit = Some(match language.to_lowercase().as_str() {
                    "java" => 4 * 1024 * 1024 * 1024_u64,     // 4 GB
                    _ => 1024 * 1024 * 1024_u64,               // 1 GB for python, cpp
                });

                // Apply language-specific environment variables
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

    #[test]
    fn test_with_language_defaults_loads_java_environment() {
        // This test requires config.json to be present in the working directory.
        // When run from the repo root via `cargo test`, config.json is found at ./config.json.
        let config = IsolateConfig::with_language_defaults("java", "test-java-env".to_string())
            .expect("with_language_defaults should succeed when config.json is present");

        let env_map: std::collections::HashMap<&str, &str> = config
            .environment
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert!(
            env_map.contains_key("JAVA_TOOL_OPTIONS"),
            "JAVA_TOOL_OPTIONS must be loaded from config.json; got env keys: {:?}",
            env_map.keys().collect::<Vec<_>>()
        );
        assert!(
            env_map.contains_key("JAVA_HOME"),
            "JAVA_HOME must be loaded from config.json"
        );
        assert!(
            env_map.contains_key("CLASSPATH"),
            "CLASSPATH must be loaded from config.json"
        );
    }

    #[test]
    fn test_with_language_defaults_loads_python_environment() {
        let config = IsolateConfig::with_language_defaults("python", "test-py-env".to_string())
            .expect("with_language_defaults should succeed");

        let env_map: std::collections::HashMap<&str, &str> = config
            .environment
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert!(
            env_map.contains_key("PYTHONDONTWRITEBYTECODE"),
            "PYTHONDONTWRITEBYTECODE must be loaded from config.json; got env keys: {:?}",
            env_map.keys().collect::<Vec<_>>()
        );
        assert!(
            env_map.contains_key("PYTHONUNBUFFERED"),
            "PYTHONUNBUFFERED must be loaded from config.json"
        );
    }

    #[test]
    fn test_uid_for_box_zero() {
        assert_eq!(IsolateConfig::uid_for_box(0), 60000);
    }

    #[test]
    fn test_uid_for_box_max() {
        assert_eq!(IsolateConfig::uid_for_box(999), 60999);
    }

    #[test]
    fn test_uid_for_box_overflow_fallback() {
        assert_eq!(IsolateConfig::uid_for_box(1000), 65534);
    }

    #[test]
    fn test_java_gets_4gb_virtual_memory_limit() {
        let config = IsolateConfig::with_language_defaults("java", "test-java-vml".to_string())
            .expect("with_language_defaults should succeed");
        assert_eq!(
            config.virtual_memory_limit,
            Some(4 * 1024 * 1024 * 1024_u64),
            "Java must get 4 GB RLIMIT_AS for compressed class pointers"
        );
    }

    #[test]
    fn test_python_gets_1gb_virtual_memory_limit() {
        let config = IsolateConfig::with_language_defaults("python", "test-py-vml".to_string())
            .expect("with_language_defaults should succeed");
        assert_eq!(
            config.virtual_memory_limit,
            Some(1024 * 1024 * 1024_u64),
            "Python must get 1 GB RLIMIT_AS"
        );
    }

    #[test]
    fn test_cpp_gets_1gb_virtual_memory_limit() {
        let config = IsolateConfig::with_language_defaults("cpp", "test-cpp-vml".to_string())
            .expect("with_language_defaults should succeed");
        assert_eq!(
            config.virtual_memory_limit,
            Some(1024 * 1024 * 1024_u64),
            "C++ must get 1 GB RLIMIT_AS"
        );
    }

    #[test]
    fn test_with_language_defaults_derives_per_box_uid() {
        let config =
            IsolateConfig::with_language_defaults("python", "rustbox/5".to_string())
                .expect("with_language_defaults should succeed");
        assert_eq!(config.uid, Some(60005), "UID should be 60000 + box_id (5)");
        assert_eq!(config.gid, Some(60005), "GID should match UID");
    }
}
