//! cgroup v1 backend implementation.

use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::cgroup::CgroupBackend;

const CONTROLLERS: [&str; 4] = ["memory", "cpu", "cpuacct", "pids"];
const REQUIRED_STRICT_CONTROLLERS: [&str; 3] = ["memory", "cpu", "cpuacct"];

#[derive(Clone, Debug)]
pub struct CgroupV1 {
    sanitized_instance: String,
    strict_mode: bool,
    enabled: bool,
    controller_paths: HashMap<String, PathBuf>,
}

impl CgroupV1 {
    pub fn new(instance_id: &str, strict_mode: bool) -> Result<Self> {
        if instance_id.is_empty() || instance_id.len() > 255 {
            return Err(IsolateError::Cgroup(
                "invalid cgroup v1 instance id length".to_string(),
            ));
        }

        let sanitized_instance = super::cgroup::sanitize_instance_id(instance_id);
        let mut controller_paths = HashMap::new();
        for controller in CONTROLLERS {
            let controller_root = Path::new("/sys/fs/cgroup").join(controller);
            if controller_root.exists() {
                controller_paths.insert(
                    controller.to_string(),
                    controller_root.join("rustbox").join(&sanitized_instance),
                );
            }
        }

        if strict_mode {
            for required in REQUIRED_STRICT_CONTROLLERS {
                if !controller_paths.contains_key(required) {
                    return Err(IsolateError::Cgroup(format!(
                        "required cgroup v1 controller '{}' is unavailable",
                        required
                    )));
                }
            }
        }

        let enabled = !controller_paths.is_empty();
        Ok(Self {
            sanitized_instance,
            strict_mode,
            enabled,
            controller_paths,
        })
    }

    fn controller_path(&self, controller: &str) -> Option<&PathBuf> {
        self.controller_paths.get(controller)
    }

    fn ensure_controller_dirs(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut failures = Vec::new();
        for (controller, path) in &self.controller_paths {
            if let Err(err) = fs::create_dir_all(path) {
                failures.push(format!("{}: {}", controller, err));
            }
        }

        if failures.is_empty() {
            return Ok(());
        }

        if self.strict_mode {
            Err(IsolateError::Cgroup(format!(
                "failed to create cgroup v1 directories: {}",
                failures.join(", ")
            )))
        } else {
            log::warn!(
                "failed to create some cgroup v1 directories (permissive mode): {}",
                failures.join(", ")
            );
            Ok(())
        }
    }

    fn read_u64(path: &Path, field_name: &str) -> Result<u64> {
        let raw = fs::read_to_string(path).map_err(|e| {
            IsolateError::Cgroup(format!(
                "failed to read {} ({}): {}",
                field_name,
                path.display(),
                e
            ))
        })?;
        raw.trim().parse::<u64>().map_err(|e| {
            IsolateError::Cgroup(format!(
                "failed to parse {} ({}): {}",
                field_name,
                path.display(),
                e
            ))
        })
    }

    fn read_optional_limit(path: &Path, field_name: &str) -> Result<Option<u64>> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(IsolateError::Cgroup(format!(
                    "failed to read {} ({}): {}",
                    field_name,
                    path.display(),
                    err
                )));
            }
        };

        let value = raw.trim();
        if value == "max" {
            return Ok(None);
        }
        value.parse::<u64>().map(Some).map_err(|err| {
            IsolateError::Cgroup(format!(
                "failed to parse {} ({}): {}",
                field_name,
                path.display(),
                err
            ))
        })
    }

    fn collect_optional_metric<T>(&self, field_name: &str, result: Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(err) if self.strict_mode => Err(IsolateError::Cgroup(format!(
                "failed collecting {} in strict mode: {}",
                field_name, err
            ))),
            Err(err) => {
                log::warn!(
                    "failed collecting {} in permissive mode: {}",
                    field_name,
                    err
                );
                Ok(None)
            }
        }
    }

    fn collect_counter_metric(&self, field_name: &str, result: Result<u64>) -> Result<u64> {
        match result {
            Ok(value) => Ok(value),
            Err(err) if self.strict_mode => Err(IsolateError::Cgroup(format!(
                "failed collecting {} in strict mode: {}",
                field_name, err
            ))),
            Err(err) => {
                log::warn!(
                    "failed collecting {} in permissive mode: {}",
                    field_name,
                    err
                );
                Ok(0)
            }
        }
    }

    fn convert_optional_u32_limit(
        &self,
        field_name: &str,
        value: Option<u64>,
    ) -> Result<Option<u32>> {
        match value {
            Some(raw) => match u32::try_from(raw) {
                Ok(parsed) => Ok(Some(parsed)),
                Err(_) if self.strict_mode => Err(IsolateError::Cgroup(format!(
                    "{} exceeds u32 limit",
                    field_name
                ))),
                Err(_) => {
                    log::warn!("{} exceeds u32 limit in permissive mode", field_name);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    fn write_value(path: &Path, value: &impl ToString, strict_mode: bool, name: &str) -> Result<()> {
        if let Err(err) = fs::write(path, value.to_string()) {
            if strict_mode {
                return Err(IsolateError::Cgroup(format!(
                    "failed to write {} ({}): {}",
                    name,
                    path.display(),
                    err
                )));
            }
            log::warn!(
                "failed to write {} ({}), continuing in permissive mode: {}",
                name,
                path.display(),
                err
            );
        }
        Ok(())
    }
}

impl CgroupBackend for CgroupV1 {
    fn backend_name(&self) -> &str {
        "cgroup_v1"
    }

    fn create(&self, _instance_id: &str) -> Result<()> {
        self.ensure_controller_dirs()
    }

    fn remove(&self, _instance_id: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut failures = Vec::new();
        for (controller, path) in &self.controller_paths {
            if !path.exists() {
                continue;
            }

            let mut removed = false;
            for _ in 0..20 {
                match fs::remove_dir(path) {
                    Ok(()) => {
                        removed = true;
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        removed = true;
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(err) => {
                        failures.push(format!("{}: {}", controller, err));
                        break;
                    }
                }
            }

            if !removed && path.exists() {
                failures.push(format!(
                    "{}: timed out removing busy cgroup {}",
                    controller,
                    path.display()
                ));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else if self.strict_mode {
            Err(IsolateError::Cgroup(format!(
                "failed removing cgroup v1 instance '{}': {}",
                self.sanitized_instance,
                failures.join(", ")
            )))
        } else {
            log::warn!(
                "failed removing some cgroup v1 paths (permissive mode): {}",
                failures.join(", ")
            );
            Ok(())
        }
    }

    fn attach_process(&self, _instance_id: &str, pid: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if pid == 0 {
            return Err(IsolateError::Cgroup(
                "invalid PID 0 for cgroup attach".to_string(),
            ));
        }

        let mut failures = Vec::new();
        for (controller, path) in &self.controller_paths {
            let tasks = path.join("tasks");
            if let Err(err) = fs::write(&tasks, pid.to_string()) {
                failures.push(format!("{}: {}", controller, err));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else if self.strict_mode {
            Err(IsolateError::Cgroup(format!(
                "failed attaching PID {} to cgroup v1: {}",
                pid,
                failures.join(", ")
            )))
        } else {
            log::warn!(
                "partial cgroup v1 attach failure for PID {} (permissive mode): {}",
                pid,
                failures.join(", ")
            );
            Ok(())
        }
    }

    fn set_memory_limit(&self, _instance_id: &str, limit_bytes: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if limit_bytes == 0 {
            return Err(IsolateError::Cgroup(
                "memory limit cannot be zero".to_string(),
            ));
        }

        let Some(memory_path) = self.controller_path("memory") else {
            if self.strict_mode {
                return Err(IsolateError::Cgroup(
                    "memory controller unavailable for cgroup v1".to_string(),
                ));
            }
            return Ok(());
        };

        // cgroup v1 enforces: memsw.limit >= memory.limit
        // On a fresh cgroup (defaults are huge), we must set memory first, then memsw.
        // On a reused cgroup with a low memsw, we must set memsw first, then memory.
        // Strategy: try memory-first; if memsw then fails, retry memsw-first.
        let mem_file = memory_path.join("memory.limit_in_bytes");
        let memsw = memory_path.join("memory.memsw.limit_in_bytes");
        let has_memsw = memsw.exists();

        Self::write_value(&mem_file, &limit_bytes, self.strict_mode, "memory.limit_in_bytes")?;

        if has_memsw && Self::write_value(&memsw, &limit_bytes, self.strict_mode, "memory.memsw.limit_in_bytes").is_err() {
            // Retry: set memsw first (raise ceiling), then memory
            let _ = Self::write_value(&memsw, &limit_bytes, false, "memory.memsw.limit_in_bytes");
            Self::write_value(&mem_file, &limit_bytes, self.strict_mode, "memory.limit_in_bytes")?;
        }

        let swappiness = memory_path.join("memory.swappiness");
        if swappiness.exists() {
            let _ = Self::write_value(&swappiness, &0u8, false, "memory.swappiness");
        }

        Ok(())
    }

    fn set_process_limit(&self, _instance_id: &str, limit: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if limit == 0 {
            return Err(IsolateError::Cgroup(
                "process limit cannot be zero".to_string(),
            ));
        }

        let Some(pids_path) = self.controller_path("pids") else {
            if self.strict_mode {
                return Err(IsolateError::Cgroup(
                    "pids controller unavailable for cgroup v1".to_string(),
                ));
            }
            return Ok(());
        };

        Self::write_value(
            &pids_path.join("pids.max"),
            &limit,
            self.strict_mode,
            "pids.max",
        )
    }

    fn set_cpu_limit(&self, _instance_id: &str, limit_usec: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let Some(cpu_path) = self.controller_path("cpu") else {
            if self.strict_mode {
                return Err(IsolateError::Cgroup(
                    "cpu controller unavailable for cgroup v1".to_string(),
                ));
            }
            return Ok(());
        };

        // Set relative CPU weight (shares). Default is 1024 = fair share.
        let shares = limit_usec.clamp(2, 262_144);
        Self::write_value(
            &cpu_path.join("cpu.shares"),
            &shares,
            self.strict_mode,
            "cpu.shares",
        )?;

        // NOTE: CFS quota (cpu.cfs_quota_us) is NOT set here.
        // CPU time enforcement uses RLIMIT_CPU (kernel sends SIGXCPU/SIGKILL)
        // and the supervisor's cgroup CPU-usage watchdog polling loop.
        // Setting CFS quota from a shares value is a semantic error —
        // shares and quota have completely different units and meaning.

        Ok(())
    }

    fn get_memory_usage(&self) -> Result<u64> {
        let Some(memory_path) = self.controller_path("memory") else {
            return Ok(0);
        };
        let usage_path = memory_path.join("memory.usage_in_bytes");
        if !usage_path.exists() {
            return Ok(0);
        }
        Self::read_u64(&usage_path, "memory.usage_in_bytes")
    }

    fn get_memory_peak(&self) -> Result<u64> {
        let Some(memory_path) = self.controller_path("memory") else {
            return Ok(0);
        };
        let peak_path = memory_path.join("memory.max_usage_in_bytes");
        if peak_path.exists() {
            return Self::read_u64(&peak_path, "memory.max_usage_in_bytes");
        }
        self.get_memory_usage()
    }

    fn get_cpu_usage(&self) -> Result<u64> {
        let Some(cpuacct_path) = self.controller_path("cpuacct") else {
            return Ok(0);
        };
        let usage_path = cpuacct_path.join("cpuacct.usage");
        if !usage_path.exists() {
            return Ok(0);
        }
        let nanos = Self::read_u64(&usage_path, "cpuacct.usage")?;
        Ok(nanos / 1_000)
    }

    fn get_process_count(&self) -> Result<u32> {
        if let Some(pids_path) = self.controller_path("pids") {
            let current_path = pids_path.join("pids.current");
            if current_path.exists() {
                let value = Self::read_u64(&current_path, "pids.current")?;
                return u32::try_from(value)
                    .map_err(|_| IsolateError::Cgroup("pids.current exceeds u32".to_string()));
            }
        }

        if let Some(cpu_path) = self.controller_path("cpu") {
            let tasks_path = cpu_path.join("tasks");
            if tasks_path.exists() {
                let content = fs::read_to_string(&tasks_path).map_err(|e| {
                    IsolateError::Cgroup(format!("failed to read {}: {}", tasks_path.display(), e))
                })?;
                let count = content.lines().filter(|l| !l.trim().is_empty()).count();
                return u32::try_from(count)
                    .map_err(|_| IsolateError::Cgroup("task count exceeds u32".to_string()));
            }
        }

        Ok(0)
    }

    fn check_oom(&self) -> Result<bool> {
        Ok(self.get_oom_kill_count()? > 0)
    }

    fn get_oom_kill_count(&self) -> Result<u64> {
        let Some(memory_path) = self.controller_path("memory") else {
            return Ok(0);
        };
        // memory.oom_control contains the actual OOM kill count.
        // memory.failcnt only counts allocation retries (false positives).
        let oom_control = memory_path.join("memory.oom_control");
        if oom_control.exists() {
            let content = std::fs::read_to_string(&oom_control).unwrap_or_default();
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("oom_kill ") {
                    return val.trim().parse::<u64>().map_err(|e| {
                        IsolateError::Cgroup(format!("failed to parse oom_kill: {}", e))
                    });
                }
            }
        }
        Ok(0)
    }

    fn collect_evidence(&self, _instance_id: &str) -> Result<CgroupEvidence> {
        let memory_limit_raw = self
            .controller_path("memory")
            .map(|path| {
                Self::read_optional_limit(
                    &path.join("memory.limit_in_bytes"),
                    "memory.limit_in_bytes",
                )
            })
            .transpose()?
            .flatten();
        let process_limit_raw = self
            .controller_path("pids")
            .map(|path| Self::read_optional_limit(&path.join("pids.max"), "pids.max"))
            .transpose()?
            .flatten();
        let process_limit = self.convert_optional_u32_limit("pids.max", process_limit_raw)?;

        let memory_peak =
            self.collect_optional_metric("memory.max_usage_in_bytes", self.get_memory_peak())?;
        let cpu_usage_usec = self.collect_optional_metric("cpuacct.usage", self.get_cpu_usage())?;
        let process_count =
            self.collect_optional_metric("pids.current/tasks", self.get_process_count())?;
        let oom_kill_count =
            self.collect_counter_metric("memory.failcnt", self.get_oom_kill_count())?;

        Ok(CgroupEvidence {
            memory_peak,
            memory_limit: memory_limit_raw,
            oom_events: oom_kill_count,
            oom_kill_events: oom_kill_count,
            cpu_usage_usec,
            process_count,
            process_limit,
        })
    }

    fn get_cgroup_path(&self, _instance_id: &str) -> PathBuf {
        self.controller_path("memory")
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"))
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.get_process_count()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::kernel::cgroup::sanitize_instance_id;

    #[test]
    fn sanitize_rewrites_path_like_instance_ids() {
        assert_eq!(sanitize_instance_id("rustbox/42"), "rustbox_42");
        assert_eq!(sanitize_instance_id("../x"), "default");
    }
}
