use crate::types::{IsolateConfig, IsolateError, Result};
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
    pub syscalls: SyscallConfig,
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
pub struct SyscallConfig {
    pub allow_exec: bool,
    pub allow_clone: Option<bool>,
    pub additional_blocked_syscalls: Option<Vec<String>>,
    pub additional_allowed_syscalls: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationConfig {
    pub enabled: bool,
    pub compiler: String,
    pub compiler_args: Vec<String>,
    pub max_compilation_time: i64,
    pub max_compilation_memory_mb: i64,
}

/// Full config.json structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBoxConfig {
    pub isolate: IsolateGlobalConfig,
    pub syscalls: GlobalSyscallConfig,
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
pub struct GlobalSyscallConfig {
    pub allow_fork: bool,
    pub allow_exec: bool,
    pub allow_clone: bool,
    pub allow_network: bool,
    pub allow_filesystem_write: bool,
    pub allow_ptrace: bool,
    pub allow_mount: bool,
    pub blocked_syscalls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub drop_capabilities: bool,
    pub use_seccomp: bool,
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

    /// Load default configuration from ./config.json
    pub fn load_default() -> Result<Self> {
        let config_path = std::env::current_dir()
            .map_err(|e| IsolateError::Config(format!("Failed to get current directory: {}", e)))?
            .join("config.json");

        if !config_path.exists() {
            return Err(IsolateError::Config(
                "config.json not found in current directory".to_string(),
            ));
        }

        Self::load_from_file(config_path)
    }

    /// Get language-specific configuration
    pub fn get_language_config(&self, language: &str) -> Option<&LanguageConfig> {
        self.languages.get(&language.to_lowercase())
    }
}

impl IsolateConfig {
    /// Create IsolateConfig with language-specific defaults from config.json
    pub fn with_language_defaults(language: &str, instance_id: String) -> Result<Self> {
        let mut config = Self::default();
        config.instance_id = instance_id;

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
