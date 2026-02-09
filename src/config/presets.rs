/// Language Runtime Envelopes
/// Implements P1-UX-001: Judge Language Presets and Minimal CLI
/// Implements P1-LANGENV-001: Versioned Language Runtime Envelopes
///
/// Per plan.md Section 14.3: Language runtime envelopes are explicit, immutable, and versioned presets.
/// Each envelope defines runtime bootstrap commands, limit policy modifiers, expected startup overhead.
use crate::config::types::IsolateConfig;
use std::collections::HashMap;

/// Language runtime envelope
/// Per plan.md: Immutable versioned presets with explicit limits/overheads/policy assumptions
#[derive(Debug, Clone)]
pub struct LanguageEnvelope {
    /// Envelope ID (e.g., "cpp17-v1", "java17-v1", "python3.11-v1")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Version of this envelope
    pub version: String,
    /// Language family
    pub language: String,
    /// Compiler command (if applicable)
    pub compiler: Option<CompilerConfig>,
    /// Runtime command
    pub runtime: RuntimeConfig,
    /// Default resource limits
    pub default_limits: ResourceLimits,
    /// Expected startup overhead (milliseconds)
    pub startup_overhead_ms: u64,
}

/// Compiler configuration
#[derive(Debug, Clone)]
pub struct CompilerConfig {
    /// Compiler executable path
    pub executable: String,
    /// Compiler arguments
    pub args: Vec<String>,
    /// Output file name
    pub output: String,
    /// Compilation timeout (seconds)
    pub timeout: u64,
}

/// Runtime configuration
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Runtime executable path
    pub executable: String,
    /// Runtime arguments (before source file)
    pub args: Vec<String>,
}

/// Resource limits for language envelope
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Memory limit (MB)
    pub memory_mb: Option<u64>,
    /// CPU time limit (seconds)
    pub cpu_time_sec: Option<u64>,
    /// Wall time limit (seconds)
    pub wall_time_sec: Option<u64>,
    /// Process limit
    pub process_limit: Option<u32>,
    /// Stack size limit (MB)
    pub stack_mb: Option<u64>,
}

impl LanguageEnvelope {
    /// Apply envelope to isolate config
    /// Per plan.md: Envelope selection must be explicit and recorded in result metadata
    pub fn apply_to_config(&self, config: &mut IsolateConfig) {
        use std::time::Duration;

        // Apply default limits (can be overridden by user)
        if let Some(mem_mb) = self.default_limits.memory_mb {
            if config.memory_limit.is_none() {
                config.memory_limit = Some(mem_mb * 1024 * 1024); // Convert MB to bytes
            }
        }

        if let Some(cpu_sec) = self.default_limits.cpu_time_sec {
            if config.cpu_time_limit.is_none() {
                config.cpu_time_limit = Some(Duration::from_secs(cpu_sec));
            }
        }

        if let Some(wall_sec) = self.default_limits.wall_time_sec {
            if config.wall_time_limit.is_none() {
                config.wall_time_limit = Some(Duration::from_secs(wall_sec));
            }
        }

        if let Some(procs) = self.default_limits.process_limit {
            if config.process_limit.is_none() {
                config.process_limit = Some(procs);
            }
        }

        log::info!("Applied language envelope: {} ({})", self.id, self.name);
    }

    /// Get envelope metadata for result recording
    pub fn get_metadata(&self) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("envelope_id".to_string(), self.id.clone());
        metadata.insert("envelope_name".to_string(), self.name.clone());
        metadata.insert("envelope_version".to_string(), self.version.clone());
        metadata.insert("language".to_string(), self.language.clone());
        metadata.insert(
            "startup_overhead_ms".to_string(),
            self.startup_overhead_ms.to_string(),
        );

        metadata
    }
}

/// Language preset registry
/// Per plan.md: C/C++, Java, Python presets documented and wired
pub struct LanguagePresets {
    envelopes: HashMap<String, LanguageEnvelope>,
}

impl LanguagePresets {
    /// Create new preset registry with default envelopes
    pub fn new() -> Self {
        let mut presets = Self {
            envelopes: HashMap::new(),
        };

        // Register default envelopes
        presets.register_cpp17_v1();
        presets.register_java17_v1();
        presets.register_python311_v1();

        presets
    }

    /// Register C++17 envelope
    fn register_cpp17_v1(&mut self) {
        let envelope = LanguageEnvelope {
            id: "cpp17-v1".to_string(),
            name: "C++17 (GCC)".to_string(),
            version: "1.0".to_string(),
            language: "cpp".to_string(),
            compiler: Some(CompilerConfig {
                executable: "/usr/bin/g++".to_string(),
                args: vec![
                    "-std=c++17".to_string(),
                    "-O2".to_string(),
                    "-Wall".to_string(),
                    "-Wextra".to_string(),
                    "-static".to_string(),
                ],
                output: "solution".to_string(),
                timeout: 30,
            }),
            runtime: RuntimeConfig {
                executable: "./solution".to_string(),
                args: vec![],
            },
            default_limits: ResourceLimits {
                memory_mb: Some(256),
                cpu_time_sec: Some(10),
                wall_time_sec: Some(15),
                process_limit: Some(1),
                stack_mb: Some(64),
            },
            startup_overhead_ms: 50,
        };

        self.envelopes.insert(envelope.id.clone(), envelope);
    }

    /// Register Java 17 envelope
    fn register_java17_v1(&mut self) {
        let envelope = LanguageEnvelope {
            id: "java17-v1".to_string(),
            name: "Java 17 (OpenJDK)".to_string(),
            version: "1.0".to_string(),
            language: "java".to_string(),
            compiler: Some(CompilerConfig {
                executable: "/usr/bin/javac".to_string(),
                args: vec!["-encoding".to_string(), "UTF-8".to_string()],
                output: "Solution.class".to_string(),
                timeout: 30,
            }),
            runtime: RuntimeConfig {
                executable: "/usr/bin/java".to_string(),
                args: vec![
                    "-Xmx256m".to_string(),
                    "-Xss1m".to_string(),
                    "-XX:+UseSerialGC".to_string(),
                    "-Dfile.encoding=UTF-8".to_string(),
                ],
            },
            default_limits: ResourceLimits {
                memory_mb: Some(512),
                cpu_time_sec: Some(10),
                wall_time_sec: Some(15),
                process_limit: Some(256),
                stack_mb: Some(64),
            },
            startup_overhead_ms: 200,
        };

        self.envelopes.insert(envelope.id.clone(), envelope);
    }

    /// Register Python 3.11 envelope
    fn register_python311_v1(&mut self) {
        let envelope = LanguageEnvelope {
            id: "python3.11-v1".to_string(),
            name: "Python 3.11".to_string(),
            version: "1.0".to_string(),
            language: "python".to_string(),
            compiler: None,
            runtime: RuntimeConfig {
                executable: "/usr/bin/python3".to_string(),
                args: vec![
                    "-B".to_string(), // Don't write .pyc files
                    "-S".to_string(), // Don't import site module
                ],
            },
            default_limits: ResourceLimits {
                memory_mb: Some(256),
                cpu_time_sec: Some(10),
                wall_time_sec: Some(15),
                process_limit: Some(1),
                stack_mb: Some(64),
            },
            startup_overhead_ms: 100,
        };

        self.envelopes.insert(envelope.id.clone(), envelope);
    }

    /// Get envelope by ID
    pub fn get(&self, id: &str) -> Option<&LanguageEnvelope> {
        self.envelopes.get(id)
    }

    /// Get envelope by language name (returns first matching version)
    pub fn get_by_language(&self, language: &str) -> Option<&LanguageEnvelope> {
        self.envelopes.values().find(|e| e.language == language)
    }

    /// List all available envelopes
    pub fn list(&self) -> Vec<&LanguageEnvelope> {
        self.envelopes.values().collect()
    }

    /// Check if envelope exists
    pub fn has(&self, id: &str) -> bool {
        self.envelopes.contains_key(id)
    }
}

impl Default for LanguagePresets {
    fn default() -> Self {
        Self::new()
    }
}

/// Get global language presets registry
pub fn get_presets() -> &'static LanguagePresets {
    use std::sync::OnceLock;
    static PRESETS: OnceLock<LanguagePresets> = OnceLock::new();
    PRESETS.get_or_init(LanguagePresets::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presets_creation() {
        let presets = LanguagePresets::new();
        assert!(presets.has("cpp17-v1"));
        assert!(presets.has("java17-v1"));
        assert!(presets.has("python3.11-v1"));
    }

    #[test]
    fn test_get_envelope() {
        let presets = LanguagePresets::new();

        let cpp = presets.get("cpp17-v1");
        assert!(cpp.is_some());
        assert_eq!(cpp.unwrap().language, "cpp");

        let java = presets.get("java17-v1");
        assert!(java.is_some());
        assert_eq!(java.unwrap().language, "java");

        let python = presets.get("python3.11-v1");
        assert!(python.is_some());
        assert_eq!(python.unwrap().language, "python");
    }

    #[test]
    fn test_get_by_language() {
        let presets = LanguagePresets::new();

        let cpp = presets.get_by_language("cpp");
        assert!(cpp.is_some());
        assert_eq!(cpp.unwrap().id, "cpp17-v1");

        let java = presets.get_by_language("java");
        assert!(java.is_some());
        assert_eq!(java.unwrap().id, "java17-v1");

        let python = presets.get_by_language("python");
        assert!(python.is_some());
        assert_eq!(python.unwrap().id, "python3.11-v1");
    }

    #[test]
    fn test_list_envelopes() {
        let presets = LanguagePresets::new();
        let list = presets.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_envelope_metadata() {
        let presets = LanguagePresets::new();
        let cpp = presets.get("cpp17-v1").unwrap();

        let metadata = cpp.get_metadata();
        assert_eq!(metadata.get("envelope_id").unwrap(), "cpp17-v1");
        assert_eq!(metadata.get("language").unwrap(), "cpp");
        assert_eq!(metadata.get("envelope_version").unwrap(), "1.0");
    }

    #[test]
    fn test_apply_to_config() {
        use std::time::Duration;

        let presets = LanguagePresets::new();
        let cpp = presets.get("cpp17-v1").unwrap();

        let mut config = IsolateConfig::default();
        // Clear defaults to test envelope application
        config.memory_limit = None;
        config.cpu_time_limit = None;
        config.wall_time_limit = None;
        config.process_limit = None;

        cpp.apply_to_config(&mut config);

        assert_eq!(config.memory_limit, Some(256 * 1024 * 1024)); // 256 MB in bytes
        assert_eq!(config.cpu_time_limit, Some(Duration::from_secs(10)));
        assert_eq!(config.wall_time_limit, Some(Duration::from_secs(15)));
        assert_eq!(config.process_limit, Some(1));
    }

    #[test]
    fn test_cpp_envelope() {
        let presets = LanguagePresets::new();
        let cpp = presets.get("cpp17-v1").unwrap();

        assert_eq!(cpp.id, "cpp17-v1");
        assert_eq!(cpp.language, "cpp");
        assert!(cpp.compiler.is_some());
        assert_eq!(cpp.startup_overhead_ms, 50);
    }

    #[test]
    fn test_java_envelope() {
        let presets = LanguagePresets::new();
        let java = presets.get("java17-v1").unwrap();

        assert_eq!(java.id, "java17-v1");
        assert_eq!(java.language, "java");
        assert!(java.compiler.is_some());
        assert_eq!(java.startup_overhead_ms, 200);
        assert_eq!(java.default_limits.memory_mb, Some(512)); // Java needs more memory
        assert_eq!(java.default_limits.process_limit, Some(256)); // JVM needs thread headroom
    }

    #[test]
    fn test_python_envelope() {
        let presets = LanguagePresets::new();
        let python = presets.get("python3.11-v1").unwrap();

        assert_eq!(python.id, "python3.11-v1");
        assert_eq!(python.language, "python");
        assert!(python.compiler.is_none()); // Python is interpreted
        assert_eq!(python.startup_overhead_ms, 100);
    }

    #[test]
    fn test_global_presets() {
        let presets = get_presets();
        assert!(presets.has("cpp17-v1"));
        assert!(presets.has("java17-v1"));
        assert!(presets.has("python3.11-v1"));
    }
}
