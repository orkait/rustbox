use crate::config::types::IsolateConfig;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct LanguageEnvelope {
    pub id: String,
    pub name: String,
    pub version: String,
    pub language: String,
    pub compiler: Option<CompilerConfig>,
    pub runtime: RuntimeConfig,
    pub default_limits: ResourceLimits,
    pub startup_overhead_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CompilerConfig {
    pub executable: String,
    pub args: Vec<String>,
    pub output: String,
    pub timeout: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub executable: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub memory_mb: Option<u64>,
    pub cpu_time_sec: Option<u64>,
    pub wall_time_sec: Option<u64>,
    pub process_limit: Option<u32>,
    pub stack_mb: Option<u64>,
}

impl LanguageEnvelope {
    pub fn apply_to_config(&self, config: &mut IsolateConfig) {
        use std::time::Duration;
        let l = &self.default_limits;
        if config.memory_limit.is_none() {
            config.memory_limit = l.memory_mb.map(|v| v * 1024 * 1024);
        }
        if config.cpu_time_limit.is_none() {
            config.cpu_time_limit = l.cpu_time_sec.map(Duration::from_secs);
        }
        if config.wall_time_limit.is_none() {
            config.wall_time_limit = l.wall_time_sec.map(Duration::from_secs);
        }
        if config.process_limit.is_none() {
            config.process_limit = l.process_limit;
        }
        log::info!("Applied language envelope: {} ({})", self.id, self.name);
    }
}

struct EnvelopeDef {
    id: &'static str,
    name: &'static str,
    language: &'static str,
    compiler: Option<(&'static str, &'static [&'static str], &'static str, u64)>,
    runtime_exe: &'static str,
    runtime_args: &'static [&'static str],
    memory_mb: u64,
    cpu_time_sec: u64,
    wall_time_sec: u64,
    process_limit: u32,
    startup_overhead_ms: u64,
}

const ENVELOPES: &[EnvelopeDef] = &[
    EnvelopeDef {
        id: "cpp17-v1",
        name: "C++17 (GCC)",
        language: "cpp",
        compiler: Some((
            "/usr/bin/g++",
            &["-std=c++17", "-O2", "-Wall", "-Wextra", "-static"],
            "solution",
            30,
        )),
        runtime_exe: "./solution",
        runtime_args: &[],
        memory_mb: 256,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 1,
        startup_overhead_ms: 50,
    },
    EnvelopeDef {
        id: "java21-v1",
        name: "Java 21 (OpenJDK)",
        language: "java",
        compiler: Some((
            "/usr/bin/javac",
            &["-encoding", "UTF-8"],
            "Solution.class",
            30,
        )),
        runtime_exe: "/usr/bin/java",
        runtime_args: &[
            "-Xmx256m",
            "-Xss1m",
            "-XX:+UseSerialGC",
            "-Dfile.encoding=UTF-8",
        ],
        memory_mb: 512,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 256,
        startup_overhead_ms: 200,
    },
    EnvelopeDef {
        id: "python3.11-v1",
        name: "Python 3.11",
        language: "python",
        compiler: None,
        runtime_exe: "/usr/bin/python3",
        runtime_args: &["-u", "-B"],
        memory_mb: 256,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 1,
        startup_overhead_ms: 100,
    },
    EnvelopeDef {
        id: "javascript-v1",
        name: "JavaScript (Bun)",
        language: "javascript",
        compiler: None,
        runtime_exe: "/usr/local/bin/bun",
        runtime_args: &["run"],
        memory_mb: 512,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 16,
        startup_overhead_ms: 50,
    },
    EnvelopeDef {
        id: "go-v1",
        name: "Go",
        language: "go",
        compiler: Some((
            "/usr/local/go/bin/go",
            &["build", "-o", "solution"],
            "solution",
            30,
        )),
        runtime_exe: "./solution",
        runtime_args: &[],
        memory_mb: 256,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 1,
        startup_overhead_ms: 50,
    },
    EnvelopeDef {
        id: "rust-v1",
        name: "Rust",
        language: "rust",
        compiler: Some((
            "/usr/local/bin/rustc",
            &["-O", "--edition", "2021", "-o", "solution"],
            "solution",
            30,
        )),
        runtime_exe: "./solution",
        runtime_args: &[],
        memory_mb: 256,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 1,
        startup_overhead_ms: 50,
    },
    EnvelopeDef {
        id: "typescript-v1",
        name: "TypeScript",
        language: "typescript",
        compiler: None,
        runtime_exe: "/usr/local/bin/bun",
        runtime_args: &["run"],
        memory_mb: 512,
        cpu_time_sec: 10,
        wall_time_sec: 15,
        process_limit: 16,
        startup_overhead_ms: 150,
    },
];

fn build_envelope(def: &EnvelopeDef) -> LanguageEnvelope {
    LanguageEnvelope {
        id: def.id.to_string(),
        name: def.name.to_string(),
        version: "1.0".to_string(),
        language: def.language.to_string(),
        compiler: def
            .compiler
            .map(|(exe, args, out, timeout)| CompilerConfig {
                executable: exe.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                output: out.to_string(),
                timeout,
            }),
        runtime: RuntimeConfig {
            executable: def.runtime_exe.to_string(),
            args: def.runtime_args.iter().map(|s| s.to_string()).collect(),
        },
        default_limits: ResourceLimits {
            memory_mb: Some(def.memory_mb),
            cpu_time_sec: Some(def.cpu_time_sec),
            wall_time_sec: Some(def.wall_time_sec),
            process_limit: Some(def.process_limit),
            stack_mb: Some(64),
        },
        startup_overhead_ms: def.startup_overhead_ms,
    }
}

pub struct LanguagePresets {
    envelopes: HashMap<String, LanguageEnvelope>,
}

impl LanguagePresets {
    pub fn new() -> Self {
        let envelopes = ENVELOPES
            .iter()
            .map(|def| {
                let e = build_envelope(def);
                (e.id.clone(), e)
            })
            .collect();
        Self { envelopes }
    }

    pub fn get(&self, id: &str) -> Option<&LanguageEnvelope> {
        self.envelopes.get(id)
    }

    pub fn get_by_language(&self, language: &str) -> Option<&LanguageEnvelope> {
        self.envelopes.values().find(|e| e.language == language)
    }

    pub fn list(&self) -> Vec<&LanguageEnvelope> {
        self.envelopes.values().collect()
    }

    pub fn has(&self, id: &str) -> bool {
        self.envelopes.contains_key(id)
    }
}

impl Default for LanguagePresets {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_presets() -> &'static LanguagePresets {
    use std::sync::OnceLock;
    static PRESETS: OnceLock<LanguagePresets> = OnceLock::new();
    PRESETS.get_or_init(LanguagePresets::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_envelopes_registered() {
        let p = LanguagePresets::new();
        for def in ENVELOPES {
            assert!(p.has(def.id), "missing {}", def.id);
            let e = p.get(def.id).unwrap();
            assert_eq!(e.language, def.language);
            assert_eq!(e.startup_overhead_ms, def.startup_overhead_ms);
            assert_eq!(e.default_limits.memory_mb, Some(def.memory_mb));
            assert_eq!(e.default_limits.process_limit, Some(def.process_limit));
            assert_eq!(e.compiler.is_some(), def.compiler.is_some());
        }
        assert_eq!(p.list().len(), ENVELOPES.len());
    }

    #[test]
    fn get_by_language_finds_all() {
        let p = LanguagePresets::new();
        for def in ENVELOPES {
            let e = p.get_by_language(def.language).unwrap();
            assert_eq!(e.id, def.id);
        }
    }

    #[test]
    fn apply_to_config_sets_defaults() {
        use std::time::Duration;
        let p = LanguagePresets::new();
        let cpp = p.get("cpp17-v1").unwrap();
        let mut config = IsolateConfig::default();
        config.memory_limit = None;
        config.cpu_time_limit = None;
        config.wall_time_limit = None;
        config.process_limit = None;
        cpp.apply_to_config(&mut config);
        assert_eq!(config.memory_limit, Some(256 * 1024 * 1024));
        assert_eq!(config.cpu_time_limit, Some(Duration::from_secs(10)));
        assert_eq!(config.wall_time_limit, Some(Duration::from_secs(15)));
        assert_eq!(config.process_limit, Some(1));
    }

    #[test]
    fn global_presets_singleton() {
        let p = get_presets();
        assert_eq!(p.list().len(), ENVELOPES.len());
    }
}
