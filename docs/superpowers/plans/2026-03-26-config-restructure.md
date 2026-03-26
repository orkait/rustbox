# Config Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate 67 dead config fields, flatten limits into one object per language, move hardcoded compiler paths/flags/limits from isolate.rs into config.json, and remove dead output_limit fields.

**Architecture:** Replace the current 6-struct config model (MemoryConfig/TimeConfig/ProcessConfig/FilesystemConfig/CompilationConfig/LanguageConfig) with a 3-struct model (LimitsConfig/RuntimeConfig/CompilationConfig + LanguageConfig). The `isolate.rs` compile_and_execute_* methods will read compiler commands and compile-phase limits from config instead of hardcoding them. Interpreted languages use `runtime` only. Compiled languages use both `compilation` and `runtime`.

**Tech Stack:** Rust, serde_json, config.json

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `config.json` | **Rewrite** | New structure with `sandbox`, `languages.*.limits`, `languages.*.runtime`, `languages.*.compilation` |
| `src/config/config.rs` | **Rewrite structs** | New `LimitsConfig`, `RuntimeConfig`, `CompilationConfig`, `LanguageConfig`, updated `with_language_defaults()` |
| `src/runtime/isolate.rs` | **Major edit** | `execute_code_string()` reads runtime/compilation from config. Remove all `compile_and_execute_c/cpp/go/rust/java` methods, replace with generic `compile_and_execute_from_config()` |
| `src/config/presets.rs` | **Update** | Align `ENVELOPES` with new config shape (compilation limits come from config now) |

**Files NOT changed:** `src/config/types.rs`, `src/exec/preexec.rs`, `src/core/types.rs`, `src/kernel/*`, `judge-service/*`

---

### Task 1: Rewrite config.json with new structure

**Files:**
- Rewrite: `config.json`

- [ ] **Step 1: Replace config.json with the new structure**

```json
{
  "sandbox": {
    "tmpfs_size_mb": 256
  },
  "languages": {
    "python": {
      "limits": {
        "memory_mb": 256,
        "virtual_memory_mb": 1024,
        "cpu_time_sec": 4,
        "wall_time_sec": 7,
        "max_processes": 10,
        "max_file_size_kb": 512,
        "max_open_files": 32
      },
      "runtime": {
        "command": ["/usr/bin/python3", "-u"],
        "source_file": "solution.py"
      },
      "environment": {
        "PYTHONPATH": "/usr/lib/python3.11:/usr/local/lib/python3.11/dist-packages",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1"
      }
    },
    "java": {
      "limits": {
        "memory_mb": 512,
        "virtual_memory_mb": 4096,
        "cpu_time_sec": 8,
        "wall_time_sec": 10,
        "max_processes": 1024,
        "max_file_size_kb": 2048,
        "max_open_files": 128
      },
      "compilation": {
        "command": ["javac", "-encoding", "UTF-8", "-proc:none", "-cp", ".", "{source}"],
        "source_file": "{class}.java",
        "limits": {
          "memory_mb": 512,
          "max_processes": 1024,
          "cpu_time_sec": 15,
          "wall_time_sec": 30,
          "fd_limit": 512,
          "file_size_mb": 256
        }
      },
      "runtime": {
        "command": ["java", "-Xmx256m", "-Xms32m", "-Xss64m", "-XX:+UseSerialGC", "-XX:+ExitOnOutOfMemoryError", "-XX:TieredStopAtLevel=1", "-XX:MaxMetaspaceSize=64m", "-Dfile.encoding=UTF-8", "-cp", ".", "{class}"],
        "source_file": null
      },
      "environment": {
        "JAVA_HOME": "/usr/lib/jvm/default-java",
        "CLASSPATH": ".",
        "JAVA_TOOL_OPTIONS": "-Xmx256m -Xms32m"
      }
    },
    "javascript": {
      "limits": {
        "memory_mb": 512,
        "virtual_memory_mb": 512,
        "cpu_time_sec": 8,
        "wall_time_sec": 12,
        "max_processes": 16,
        "max_file_size_kb": 512,
        "max_open_files": 64
      },
      "runtime": {
        "command": ["/usr/local/bin/bun", "run"],
        "source_file": "solution.js"
      },
      "environment": {}
    },
    "typescript": {
      "limits": {
        "memory_mb": 512,
        "virtual_memory_mb": 2048,
        "cpu_time_sec": 8,
        "wall_time_sec": 12,
        "max_processes": 16,
        "max_file_size_kb": 512,
        "max_open_files": 128
      },
      "runtime": {
        "command": ["/usr/local/bin/bun", "run"],
        "source_file": "solution.ts"
      },
      "environment": {}
    },
    "cpp": {
      "limits": {
        "memory_mb": 512,
        "virtual_memory_mb": 1024,
        "cpu_time_sec": 8,
        "wall_time_sec": 10,
        "max_processes": 8,
        "max_file_size_kb": 1024,
        "max_open_files": 64
      },
      "compilation": {
        "command": ["/usr/bin/g++", "-pipe", "-o", "solution", "{source}", "-std=c++17", "-O2", "-DONLINE_JUDGE"],
        "source_file": "solution.cpp",
        "limits": {
          "memory_mb": 256,
          "max_processes": 120,
          "cpu_time_sec": 15,
          "wall_time_sec": 30
        }
      },
      "runtime": {
        "command": ["./solution"],
        "source_file": null
      },
      "environment": {}
    },
    "c": {
      "limits": {
        "memory_mb": 256,
        "virtual_memory_mb": 1024,
        "cpu_time_sec": 8,
        "wall_time_sec": 10,
        "max_processes": 8,
        "max_file_size_kb": 1024,
        "max_open_files": 32
      },
      "compilation": {
        "command": ["/usr/bin/gcc", "-pipe", "-o", "solution", "{source}", "-std=c17", "-O2", "-lm", "-DONLINE_JUDGE"],
        "source_file": "solution.c",
        "limits": {
          "memory_mb": 256,
          "max_processes": 120,
          "cpu_time_sec": 15,
          "wall_time_sec": 30
        }
      },
      "runtime": {
        "command": ["./solution"],
        "source_file": null
      },
      "environment": {}
    },
    "go": {
      "limits": {
        "memory_mb": 256,
        "virtual_memory_mb": 1024,
        "cpu_time_sec": 8,
        "wall_time_sec": 10,
        "max_processes": 1024,
        "max_file_size_kb": 1024,
        "max_open_files": 64
      },
      "compilation": {
        "command": ["/usr/local/go/bin/go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "solution", "{source}"],
        "source_file": "solution.go",
        "limits": {
          "memory_mb": 1024,
          "max_processes": 1024,
          "cpu_time_sec": 15,
          "wall_time_sec": 30,
          "fd_limit": 1024,
          "file_size_mb": 256
        }
      },
      "runtime": {
        "command": ["./solution"],
        "source_file": null
      },
      "environment": {
        "CGO_ENABLED": "0",
        "GOCACHE": "/tmp/go-cache",
        "GOPATH": "/tmp/gopath",
        "HOME": "/tmp"
      }
    },
    "rust": {
      "limits": {
        "memory_mb": 256,
        "virtual_memory_mb": 1024,
        "cpu_time_sec": 8,
        "wall_time_sec": 15,
        "max_processes": 64,
        "max_file_size_kb": 1024,
        "max_open_files": 64
      },
      "compilation": {
        "command": ["/usr/local/bin/rustc", "-O", "--edition", "2021", "-C", "codegen-units=1", "-o", "solution", "{source}"],
        "source_file": "solution.rs",
        "limits": {
          "memory_mb": 1024,
          "max_processes": 64,
          "cpu_time_sec": 15,
          "wall_time_sec": 30,
          "fd_limit": 512,
          "file_size_mb": 256
        }
      },
      "runtime": {
        "command": ["./solution"],
        "source_file": null
      },
      "environment": {}
    }
  }
}
```

- [ ] **Step 2: Verify JSON is valid**

Run: `python3 -c "import json; json.load(open('config.json'))"`
Expected: no output (success)

---

### Task 2: Rewrite config.rs structs and parsing

**Files:**
- Rewrite: `src/config/config.rs` (structs + `with_language_defaults()`)

- [ ] **Step 1: Replace all config structs**

Replace lines 7-84 (all structs + defaults) with:

```rust
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

fn default_compile_memory_mb() -> u64 { 256 }
fn default_compile_max_processes() -> u32 { 120 }
fn default_compile_cpu_time_sec() -> u64 { 15 }
fn default_compile_wall_time_sec() -> u64 { 30 }

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
```

- [ ] **Step 2: Update `with_language_defaults()` to use new field names**

Replace lines 153-207 with:

```rust
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
```

- [ ] **Step 3: Update tests**

Replace the test module with:

```rust
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
```

- [ ] **Step 4: Compile check**

Run: `cargo check -p rustbox`
Expected: may fail until isolate.rs is updated (Task 3). If so, temporarily comment out `execute_code_string` callers and verify config parsing compiles.

- [ ] **Step 5: Commit**

```bash
git add config.json src/config/config.rs
git commit -m "refactor: restructure config.json - flatten limits, add runtime/compilation sections"
```

---

### Task 3: Rewrite isolate.rs to read from config

**Files:**
- Modify: `src/runtime/isolate.rs` (lines 229-579)

- [ ] **Step 1: Add a method to load language config**

Add to the `Isolate` impl block (after `ensure_workdir`):

```rust
fn load_language_config(language: &str) -> Option<(crate::config::config::LanguageConfig, crate::config::config::SandboxConfig)> {
    crate::config::config::RustBoxConfig::load_default()
        .ok()
        .and_then(|cfg| {
            let sandbox = cfg.sandbox.clone();
            cfg.languages.get(&language.to_lowercase()).cloned().map(|l| (l, sandbox))
        })
}
```

- [ ] **Step 2: Rewrite `execute_code_string` to be config-driven**

Replace the entire `execute_code_string` method (lines 229-263) and all `compile_and_execute_*` methods (lines 409-579) with:

```rust
pub fn execute_code_string(
    &mut self,
    language: &str,
    code: &str,
    overrides: &ExecutionOverrides,
) -> Result<ExecutionResult> {
    let lang_key = language.to_lowercase();
    let lang_key = match lang_key.as_str() {
        "py" => "python",
        "c++" | "cxx" => "cpp",
        "js" => "javascript",
        "ts" => "typescript",
        "rs" => "rust",
        other => other,
    };

    let (lang_cfg, _sandbox_cfg) = Self::load_language_config(lang_key)
        .ok_or_else(|| IsolateError::Config(format!("Unsupported language: {}", language)))?;

    if let Some(ref comp) = lang_cfg.compilation {
        self.compile_and_execute_from_config(code, lang_key, &lang_cfg, comp, overrides)
    } else {
        self.execute_interpreted_from_config(code, &lang_cfg, overrides)
    }
}

fn execute_interpreted_from_config(
    &mut self,
    code: &str,
    lang_cfg: &crate::config::config::LanguageConfig,
    overrides: &ExecutionOverrides,
) -> Result<ExecutionResult> {
    self.ensure_workdir()?;
    self.wipe_workdir();

    let source_file_name = lang_cfg.runtime.source_file.as_deref()
        .ok_or_else(|| IsolateError::Config("interpreted language must have runtime.source_file".into()))?;
    let source_file = self.config.workdir.join(source_file_name);

    let mut command: Vec<String> = lang_cfg.runtime.command.clone();
    command.push(source_file.to_string_lossy().to_string());

    write_source_no_follow(&source_file, code)?;
    let result = self.execute_with_overrides(&command, overrides);
    let _ = fs::remove_file(&source_file);
    result
}

fn compile_and_execute_from_config(
    &mut self,
    code: &str,
    lang_key: &str,
    lang_cfg: &crate::config::config::LanguageConfig,
    comp: &crate::config::config::CompilationConfig,
    overrides: &ExecutionOverrides,
) -> Result<ExecutionResult> {
    self.ensure_workdir()?;
    self.wipe_workdir();

    let source_name = Self::resolve_source_file(&comp.source_file, code, lang_key);
    let source_file = self.config.workdir.join(&source_name);
    write_source_no_follow(&source_file, code)?;

    let compile_cmd: Vec<String> = comp.command.iter()
        .map(|arg| arg.replace("{source}", &source_name)
                      .replace("{class}", &Self::extract_class_name(code, lang_key)))
        .collect();

    let run_cmd: Vec<String> = lang_cfg.runtime.command.iter()
        .map(|arg| arg.replace("{class}", &Self::extract_class_name(code, lang_key)))
        .collect();

    let saved = self.config.clone();
    Self::apply_compile_limits(&mut self.config, &saved, comp, overrides);
    self.update_cgroup_limits();

    let compile_result = match self.execute(&compile_cmd, None) {
        Ok(r) => r,
        Err(e) => {
            self.config = saved;
            self.update_cgroup_limits();
            self.wipe_workdir();
            return Err(e);
        }
    };

    if !compile_result.success {
        self.config = saved;
        self.update_cgroup_limits();
        self.wipe_workdir();
        let prefix = format!("{} Compilation Error", lang_key);
        return Ok(Self::build_compile_failure_result(
            compile_result,
            &prefix,
            "compilation failed",
        ));
    }

    let _ = fs::remove_file(&source_file);
    self.config = saved;
    self.update_cgroup_limits();
    let result = self.execute_with_overrides(&run_cmd, overrides);
    self.wipe_workdir();
    result
}

fn apply_compile_limits(
    config: &mut IsolateConfig,
    original: &IsolateConfig,
    comp: &crate::config::config::CompilationConfig,
    overrides: &ExecutionOverrides,
) {
    let limits = comp.limits.as_ref();
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        config.strict_mode = false;
        config.allow_degraded = true;
    }

    let mem_mb = limits.map(|l| l.memory_mb).unwrap_or(256);
    config.memory_limit = Some(
        overrides.max_memory
            .map(|mb| mb * 1024 * 1024)
            .unwrap_or(mem_mb * 1024 * 1024),
    );

    config.process_limit = Some(limits.map(|l| l.max_processes).unwrap_or(120));

    let cpu = limits.map(|l| l.cpu_time_sec).unwrap_or(15);
    let wall = limits.map(|l| l.wall_time_sec).unwrap_or(30);
    let orig_cpu = original.cpu_time_limit.map(|d| d.as_secs()).unwrap_or(8);
    let orig_wall = original.wall_time_limit.map(|d| d.as_secs()).unwrap_or(10);
    let final_cpu = overrides.max_cpu.or(overrides.max_time).unwrap_or(orig_cpu).max(cpu);
    let final_wall = overrides.max_wall_time.unwrap_or(orig_wall).max(wall);
    config.cpu_time_limit = Some(Duration::from_secs(final_cpu));
    config.time_limit = Some(Duration::from_secs(final_cpu));
    config.wall_time_limit = Some(Duration::from_secs(final_wall));

    if let Some(fd) = limits.and_then(|l| l.fd_limit) {
        config.fd_limit = Some(fd);
    }
    if let Some(fs_mb) = limits.and_then(|l| l.file_size_mb) {
        config.file_size_limit = Some(fs_mb * 1024 * 1024);
    }
}

fn resolve_source_file(template: &str, code: &str, lang_key: &str) -> String {
    if template.contains("{class}") {
        let class = Self::extract_class_name(code, lang_key);
        template.replace("{class}", &class)
    } else {
        template.to_string()
    }
}

fn extract_class_name(code: &str, lang_key: &str) -> String {
    if lang_key == "java" {
        extract_java_class_name(code).unwrap_or_else(|| "Main".to_string())
    } else {
        "Main".to_string()
    }
}
```

- [ ] **Step 3: Add Go compile-phase environment**

In `compile_and_execute_from_config`, after `apply_compile_limits`, add Go-specific compile env from config.json's `environment` section. This is already handled because `with_language_defaults()` loads `lang.environment` into `config.environment`. The Go environment (CGO_ENABLED, GOCACHE, etc.) is now in config.json, so the existing env loading handles it. No additional code needed.

However, the Go-specific compile env (GOTMPDIR, GONOSUMCHECK, GOFLAGS, HOME) that was hardcoded in `compile_and_execute_go()` needs to move to config.json. Update the Go `environment` section in config.json (already done in Task 1 - verify it includes GOTMPDIR, GONOSUMCHECK, GOFLAGS).

- [ ] **Step 4: Remove the old per-language compile methods**

Delete these methods entirely from `isolate.rs`:
- `compile_and_execute_c()` (was ~lines 409-436)
- `compile_and_execute_go()` (was ~lines 438-477)
- `compile_and_execute_rust()` (was ~lines 479-510)
- `compile_and_execute_cpp()` (was ~lines 512-538)
- `compile_and_execute_java()` (was ~lines 540-579)
- `execute_interpreted()` (was ~lines 266-284)
- `configure_compile_phase()` (was ~lines 286-316)

Keep: `compile_and_execute()` generic method if it's still used, or remove if fully replaced.

- [ ] **Step 5: Compile check**

Run: `cargo check --all`
Expected: clean compilation

- [ ] **Step 6: Run tests**

Run: `cargo test --all --lib`
Expected: all unit tests pass

- [ ] **Step 7: Commit**

```bash
git add src/runtime/isolate.rs
git commit -m "refactor: isolate.rs reads compiler paths/flags/limits from config.json"
```

---

### Task 4: Update presets.rs to align with new config

**Files:**
- Modify: `src/config/presets.rs`

- [ ] **Step 1: Update `ENVELOPES` compiler fields to reference config values**

The presets are used as fallback defaults and for the judge CLI `check-deps`. Update the compiler executable paths and args to match config.json. The `EnvelopeDef` struct already has `compiler: Option<(&str, &[&str], &str, u64)>` which stores `(exe, args, output, timeout)`.

Update each envelope's compiler path to match config.json:
- `cpp17-v1`: compiler exe `/usr/bin/g++`, args `["-std=c++17", "-O2", "-pipe", "-DONLINE_JUDGE"]`
- `java21-v1`: compiler exe `javac`, args `["-encoding", "UTF-8", "-proc:none"]`
- `go-v1`: compiler exe `/usr/local/go/bin/go`, args `["build", "-trimpath", "-ldflags", "-s -w"]`
- `rust-v1`: compiler exe `/usr/local/bin/rustc`, args `["-O", "--edition", "2021", "-C", "codegen-units=1"]`

These should already match - verify and fix any discrepancies.

- [ ] **Step 2: Compile and test**

Run: `cargo test --all --lib`
Expected: all pass

- [ ] **Step 3: Commit**

```bash
git add src/config/presets.rs
git commit -m "chore: align presets.rs with new config.json structure"
```

---

### Task 5: Add missing Go compile env to config.json

**Files:**
- Modify: `config.json`

- [ ] **Step 1: Add Go compile-specific env vars**

The old `compile_and_execute_go()` hardcoded these env vars for the compile phase only:
- `GOTMPDIR=/tmp`
- `GONOSUMCHECK=*`
- `GOFLAGS=-buildvcs=false`

These should be in the Go `environment` section in config.json. Update the Go language entry:

```json
"environment": {
  "CGO_ENABLED": "0",
  "GOCACHE": "/tmp/go-cache",
  "GOPATH": "/tmp/gopath",
  "GOTMPDIR": "/tmp",
  "GONOSUMCHECK": "*",
  "GOFLAGS": "-buildvcs=false",
  "HOME": "/tmp"
}
```

- [ ] **Step 2: Commit**

```bash
git add config.json
git commit -m "chore: add missing Go compile env vars to config.json"
```

---

### Task 6: Final verification

- [ ] **Step 1: Full compile**

Run: `cargo check --all`
Expected: clean

- [ ] **Step 2: All unit tests**

Run: `cargo test --all --lib`
Expected: all pass

- [ ] **Step 3: Trybuild tests**

Run: `cargo test --test trybuild`
Expected: all pass

- [ ] **Step 4: Verify config is valid**

Run: `cargo run --bin judge -- check-deps --verbose`
Expected: language detection works

- [ ] **Step 5: Commit any final fixups**

```bash
git add -A
git commit -m "refactor: complete config restructure - remove 67 dead fields, config-driven compilation"
```
