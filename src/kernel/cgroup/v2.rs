/// Cgroup v2 backend implementation
/// Implements P1-CGROUP2-001: v2 OOM Semantics and memory.oom.group
/// Implements P1-CGROUP2-002: v2 Peak Memory Accounting
/// Per plan.md Section 8.3: v2 Required Semantics

use crate::config::types::{CgroupEvidence, IsolateError, Result};
use crate::kernel::cgroup::backend::CgroupBackend;
use std::fs;
use std::path::PathBuf;

/// Cgroup v2 backend
pub struct CgroupV2 {
    base_path: PathBuf,
    instance_id: String,
    strict_mode: bool,
}

impl CgroupV2 {
    /// Create new cgroup v2 backend with default base path.
    pub fn new(instance_id: &str, strict_mode: bool) -> Result<Self> {
        Self::with_base_path("/sys/fs/cgroup/rustbox", instance_id, strict_mode)
    }

    /// Create new cgroup v2 backend with explicit base path (used by tests).
    pub fn with_base_path(base_path: &str, instance_id: &str, strict_mode: bool) -> Result<Self> {
        Ok(CgroupV2 {
            base_path: PathBuf::from(base_path),
            instance_id: instance_id.to_string(),
            strict_mode,
        })
    }

    /// Get cgroup path for instance.
    fn instance_path(&self, instance_id: &str) -> PathBuf {
        self.base_path.join(instance_id)
    }

    fn current_instance_path(&self) -> PathBuf {
        self.instance_path(&self.instance_id)
    }

    fn read_u64_file(path: &PathBuf, name: &str) -> Result<u64> {
        let content = fs::read_to_string(path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read {}: {}", name, e)))?;
        content
            .trim()
            .parse::<u64>()
            .map_err(|e| IsolateError::Cgroup(format!("Failed to parse {}: {}", name, e)))
    }

    fn read_optional_limit(path: &PathBuf, name: &str) -> Result<Option<u64>> {
        let content = fs::read_to_string(path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read {}: {}", name, e)))?;
        let value = content.trim();
        if value == "max" {
            Ok(None)
        } else {
            let parsed = value
                .parse::<u64>()
                .map_err(|e| IsolateError::Cgroup(format!("Failed to parse {}: {}", name, e)))?;
            Ok(Some(parsed))
        }
    }

    fn read_cpu_usage_internal(&self, instance_id: &str) -> Result<u64> {
        let path = self.instance_path(instance_id).join("cpu.stat");
        let content = fs::read_to_string(&path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read cpu.stat: {}", e)))?;

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                if key == "usage_usec" {
                    return value.parse::<u64>().map_err(|e| {
                        IsolateError::Cgroup(format!("Failed to parse cpu.stat usage_usec: {}", e))
                    });
                }
            }
        }

        Err(IsolateError::Cgroup(
            "cpu.stat missing usage_usec".to_string(),
        ))
    }

    fn read_process_count_internal(&self, instance_id: &str) -> Result<u32> {
        let path = self.instance_path(instance_id);

        let pids_current_path = path.join("pids.current");
        if pids_current_path.exists() {
            let count = Self::read_u64_file(&pids_current_path, "pids.current")?;
            return u32::try_from(count)
                .map_err(|_| IsolateError::Cgroup("pids.current exceeds u32".to_string()));
        }

        let procs_path = path.join("cgroup.procs");
        let content = fs::read_to_string(&procs_path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read cgroup.procs: {}", e)))?;
        Ok(content.lines().filter(|line| !line.trim().is_empty()).count() as u32)
    }

    /// Read memory.peak (kernel 5.19+) with fallback to memory.current.
    fn get_peak_memory_internal(&self, instance_id: &str) -> Result<u64> {
        let path = self.instance_path(instance_id);
        let peak_path = path.join("memory.peak");

        if peak_path.exists() {
            return Self::read_u64_file(&peak_path, "memory.peak");
        }

        let current_path = path.join("memory.current");
        Self::read_u64_file(&current_path, "memory.current")
    }

    /// Parse memory.events for OOM detection.
    /// Returns (oom_count, oom_kill_count).
    fn check_oom_events_internal(&self, instance_id: &str) -> Result<(u64, u64)> {
        let path = self.instance_path(instance_id);
        let events_path = path.join("memory.events");

        if !events_path.exists() {
            return Ok((0, 0));
        }

        let content = fs::read_to_string(&events_path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read memory.events: {}", e)))?;

        let mut oom_count = 0;
        let mut oom_kill_count = 0;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                match parts[0] {
                    "oom" => oom_count = parts[1].parse::<u64>().unwrap_or(0),
                    "oom_kill" => oom_kill_count = parts[1].parse::<u64>().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok((oom_count, oom_kill_count))
    }
}

impl CgroupBackend for CgroupV2 {
    fn backend_name(&self) -> &str {
        "cgroup_v2"
    }

    fn create(&self, instance_id: &str) -> Result<()> {
        let path = self.instance_path(instance_id);

        // Create cgroup directory
        fs::create_dir_all(&path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to create cgroup: {}", e)))?;

        // Set memory.oom.group=1 in strict mode (when supported)
        let oom_group_path = path.join("memory.oom.group");
        if oom_group_path.exists() {
            if let Err(e) = fs::write(&oom_group_path, "1") {
                if self.strict_mode {
                    return Err(IsolateError::Cgroup(format!(
                        "Failed to set memory.oom.group: {}",
                        e
                    )));
                }
                log::warn!("Failed to set memory.oom.group (permissive mode): {}", e);
            }
        }

        Ok(())
    }

    fn remove(&self, instance_id: &str) -> Result<()> {
        let path = self.instance_path(instance_id);

        if path.exists() {
            fs::remove_dir(&path)
                .map_err(|e| IsolateError::Cgroup(format!("Failed to remove cgroup: {}", e)))?;
        }

        Ok(())
    }

    fn attach_process(&self, instance_id: &str, pid: u32) -> Result<()> {
        let path = self.instance_path(instance_id);
        let procs_path = path.join("cgroup.procs");

        fs::write(&procs_path, pid.to_string()).map_err(|e| {
            IsolateError::Cgroup(format!("Failed to attach process to cgroup: {}", e))
        })?;

        Ok(())
    }

    fn set_memory_limit(&self, instance_id: &str, limit_bytes: u64) -> Result<()> {
        let path = self.instance_path(instance_id);
        let limit_path = path.join("memory.max");

        fs::write(&limit_path, limit_bytes.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set memory limit: {}", e)))?;

        Ok(())
    }

    fn set_process_limit(&self, instance_id: &str, limit: u32) -> Result<()> {
        let path = self.instance_path(instance_id);
        let limit_path = path.join("pids.max");

        fs::write(&limit_path, limit.to_string()).map_err(|e| {
            IsolateError::Cgroup(format!("Failed to set process limit: {}", e))
        })?;

        Ok(())
    }

    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()> {
        let path = self.instance_path(instance_id);

        // Convert microseconds to weight (v2 uses cpu.weight instead of cpu.shares).
        // Default weight is 100, range is 1-10000.
        let weight = (limit_usec / 1000).clamp(1, 10000);

        let weight_path = path.join("cpu.weight");
        fs::write(&weight_path, weight.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set CPU weight: {}", e)))?;

        Ok(())
    }

    fn get_memory_usage(&self) -> Result<u64> {
        let current_path = self.current_instance_path().join("memory.current");
        Self::read_u64_file(&current_path, "memory.current")
    }

    fn get_memory_peak(&self) -> Result<u64> {
        self.get_peak_memory_internal(&self.instance_id)
    }

    fn get_cpu_usage(&self) -> Result<u64> {
        self.read_cpu_usage_internal(&self.instance_id)
    }

    fn get_process_count(&self) -> Result<u32> {
        self.read_process_count_internal(&self.instance_id)
    }

    fn check_oom(&self) -> Result<bool> {
        let (oom_count, oom_kill_count) = self.check_oom_events_internal(&self.instance_id)?;
        Ok(oom_count > 0 || oom_kill_count > 0)
    }

    fn get_oom_kill_count(&self) -> Result<u64> {
        let (_, oom_kill_count) = self.check_oom_events_internal(&self.instance_id)?;
        Ok(oom_kill_count)
    }

    fn collect_evidence(&self, instance_id: &str) -> Result<CgroupEvidence> {
        let (oom_count, oom_kill_count) = self.check_oom_events_internal(instance_id)?;
        let path = self.instance_path(instance_id);

        let memory_limit = Self::read_optional_limit(&path.join("memory.max"), "memory.max")?;
        let process_limit = Self::read_optional_limit(&path.join("pids.max"), "pids.max")?
            .and_then(|v| u32::try_from(v).ok());

        Ok(CgroupEvidence {
            memory_peak: Some(self.get_peak_memory_internal(instance_id).unwrap_or(0)),
            memory_limit,
            oom_events: oom_count,
            oom_kill_events: oom_kill_count,
            cpu_usage_usec: self.read_cpu_usage_internal(instance_id).ok(),
            process_count: self.read_process_count_internal(instance_id).ok(),
            process_limit,
        })
    }

    fn get_cgroup_path(&self, instance_id: &str) -> PathBuf {
        self.instance_path(instance_id)
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.get_process_count()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_v2_creation() {
        let cgroup = CgroupV2::with_base_path("/tmp/test_cgroup_v2", "test_instance", false);
        assert!(cgroup.is_ok());
    }

    #[test]
    fn test_instance_path() {
        let cgroup =
            CgroupV2::with_base_path("/tmp/test_cgroup_v2", "test_instance", false).unwrap();
        let path = cgroup.instance_path("test_instance");
        assert_eq!(path, PathBuf::from("/tmp/test_cgroup_v2/test_instance"));
    }
}
