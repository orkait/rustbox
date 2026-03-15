//! cgroup v2 (unified hierarchy) backend implementation.

use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::cgroup::CgroupBackend;

const CPU_MAX_PERIOD_USEC: u64 = 100_000;
const MIN_CPU_QUOTA_USEC: u64 = 1_000;
const MIN_CPU_SHARES: u64 = 2;
const MAX_CPU_SHARES: u64 = 262_144;
const MIN_CPU_WEIGHT: u64 = 1;
const MAX_CPU_WEIGHT: u64 = 10_000;

pub struct CgroupV2 {
    base_path: PathBuf,
    instance_id: String,
    strict_mode: bool,
}

impl CgroupV2 {
    pub fn new(instance_id: &str, strict_mode: bool) -> Result<Self> {
        Self::with_base_path("/sys/fs/cgroup/rustbox", instance_id, strict_mode)
    }

    pub fn with_base_path(base_path: &str, instance_id: &str, strict_mode: bool) -> Result<Self> {
        if instance_id.is_empty() || instance_id.len() > 255 {
            return Err(IsolateError::Cgroup(
                "invalid cgroup v2 instance id length".to_string(),
            ));
        }

        Ok(Self {
            base_path: PathBuf::from(base_path),
            instance_id: super::cgroup::sanitize_instance_id(instance_id),
            strict_mode,
        })
    }

    fn instance_path(&self, instance_id: &str) -> PathBuf {
        self.base_path.join(super::cgroup::sanitize_instance_id(instance_id))
    }

    fn current_instance_path(&self) -> PathBuf {
        self.instance_path(&self.instance_id)
    }

    fn read_u64_file(path: &Path, name: &str) -> Result<u64> {
        let content = fs::read_to_string(path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to read {}: {}", name, e)))?;
        content
            .trim()
            .parse::<u64>()
            .map_err(|e| IsolateError::Cgroup(format!("failed to parse {}: {}", name, e)))
    }

    fn read_optional_limit(path: &Path, name: &str) -> Result<Option<u64>> {
        let content = fs::read_to_string(path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to read {}: {}", name, e)))?;
        let value = content.trim();
        if value == "max" {
            Ok(None)
        } else {
            let parsed = value
                .parse::<u64>()
                .map_err(|e| IsolateError::Cgroup(format!("failed to parse {}: {}", name, e)))?;
            Ok(Some(parsed))
        }
    }

    fn cpu_max_value(limit_usec: u64) -> Result<String> {
        if limit_usec == 0 {
            return Err(IsolateError::Cgroup("cpu limit cannot be zero".to_string()));
        }

        Ok(format!(
            "{} {}",
            limit_usec.max(MIN_CPU_QUOTA_USEC),
            CPU_MAX_PERIOD_USEC
        ))
    }

    fn cpu_weight_from_shares(shares: u64) -> u64 {
        let clamped = shares.clamp(MIN_CPU_SHARES, MAX_CPU_SHARES);
        let numerator = (clamped - MIN_CPU_SHARES) * (MAX_CPU_WEIGHT - MIN_CPU_WEIGHT);
        let denominator = MAX_CPU_SHARES - MIN_CPU_SHARES;
        (numerator / denominator) + MIN_CPU_WEIGHT
    }

    fn collect_optional_metric<T>(&self, name: &str, result: Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(err) if self.strict_mode => Err(IsolateError::Cgroup(format!(
                "failed collecting {} in strict mode: {}",
                name, err
            ))),
            Err(err) => {
                log::warn!("failed collecting {} in permissive mode: {}", name, err);
                Ok(None)
            }
        }
    }

    fn convert_optional_u32_limit(&self, name: &str, value: Option<u64>) -> Result<Option<u32>> {
        match value {
            Some(raw) => match u32::try_from(raw) {
                Ok(parsed) => Ok(Some(parsed)),
                Err(_) if self.strict_mode => {
                    Err(IsolateError::Cgroup(format!("{} exceeds u32 limit", name)))
                }
                Err(_) => {
                    log::warn!("{} exceeds u32 limit in permissive mode", name);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    fn read_cpu_usage_internal(&self, instance_id: &str) -> Result<u64> {
        let path = self.instance_path(instance_id).join("cpu.stat");
        let content = fs::read_to_string(&path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to read cpu.stat: {}", e)))?;

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                if key == "usage_usec" {
                    return value.parse::<u64>().map_err(|e| {
                        IsolateError::Cgroup(format!("failed to parse cpu.stat usage_usec: {}", e))
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

        let pids_current = path.join("pids.current");
        if pids_current.exists() {
            let count = Self::read_u64_file(&pids_current, "pids.current")?;
            return u32::try_from(count)
                .map_err(|_| IsolateError::Cgroup("pids.current exceeds u32".to_string()));
        }

        let procs_path = path.join("cgroup.procs");
        let content = fs::read_to_string(&procs_path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to read cgroup.procs: {}", e)))?;
        let count = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        u32::try_from(count).map_err(|_| IsolateError::Cgroup("process count overflow".to_string()))
    }

    fn get_peak_memory_internal(&self, instance_id: &str) -> Result<u64> {
        let path = self.instance_path(instance_id);
        let peak_path = path.join("memory.peak");
        if peak_path.exists() {
            return Self::read_u64_file(&peak_path, "memory.peak");
        }

        let current_path = path.join("memory.current");
        Self::read_u64_file(&current_path, "memory.current")
    }

    fn check_oom_events_internal(&self, instance_id: &str) -> Result<(u64, u64)> {
        let events_path = self.instance_path(instance_id).join("memory.events");
        if !events_path.exists() {
            return Ok((0, 0));
        }

        let content = fs::read_to_string(&events_path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to read memory.events: {}", e)))?;

        let mut oom_count = 0;
        let mut oom_kill_count = 0;

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                match key {
                    "oom" => {
                        oom_count = value.parse::<u64>().map_err(|e| {
                            IsolateError::Cgroup(format!(
                                "failed to parse memory.events oom value: {}",
                                e
                            ))
                        })?;
                    }
                    "oom_kill" => {
                        oom_kill_count = value.parse::<u64>().map_err(|e| {
                            IsolateError::Cgroup(format!(
                                "failed to parse memory.events oom_kill value: {}",
                                e
                            ))
                        })?;
                    }
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

        fs::create_dir_all(&path)
            .map_err(|e| IsolateError::Cgroup(format!("failed to create cgroup: {}", e)))?;

        let oom_group_path = path.join("memory.oom.group");
        if oom_group_path.exists() {
            if let Err(err) = fs::write(&oom_group_path, "1") {
                if self.strict_mode {
                    return Err(IsolateError::Cgroup(format!(
                        "failed to set memory.oom.group: {}",
                        err
                    )));
                }
                log::warn!("failed to set memory.oom.group in permissive mode: {}", err);
            }
        }

        Ok(())
    }

    fn remove(&self, instance_id: &str) -> Result<()> {
        let path = self.instance_path(instance_id);

        if path.exists() {
            let kill_path = path.join("cgroup.kill");
            if kill_path.exists() {
                let _ = fs::write(&kill_path, "1");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            fs::remove_dir(&path)
                .map_err(|e| IsolateError::Cgroup(format!("failed to remove cgroup: {}", e)))?;
        }

        Ok(())
    }

    fn attach_process(&self, instance_id: &str, pid: u32) -> Result<()> {
        if pid == 0 {
            return Err(IsolateError::Cgroup("invalid PID 0 for cgroup attach".to_string()));
        }

        let procs_path = self.instance_path(instance_id).join("cgroup.procs");

        fs::write(&procs_path, pid.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("failed to attach process: {}", e)))?;
        Ok(())
    }

    fn set_memory_limit(&self, instance_id: &str, limit_bytes: u64) -> Result<()> {
        if limit_bytes == 0 {
            return Err(IsolateError::Cgroup("memory limit cannot be zero".to_string()));
        }
        let path = self.instance_path(instance_id);

        fs::write(path.join("memory.max"), limit_bytes.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("failed to set memory.max: {}", e)))?;

        if let Err(err) = fs::write(path.join("memory.swap.max"), "0") {
            if self.strict_mode {
                return Err(IsolateError::Cgroup(format!(
                    "failed to set memory.swap.max=0: {}",
                    err
                )));
            }
            log::warn!(
                "failed to set memory.swap.max=0 in permissive mode: {}",
                err
            );
        }

        Ok(())
    }

    fn set_process_limit(&self, instance_id: &str, limit: u32) -> Result<()> {
        if limit == 0 {
            return Err(IsolateError::Cgroup("process limit cannot be zero".to_string()));
        }
        let limit_path = self.instance_path(instance_id).join("pids.max");
        fs::write(&limit_path, limit.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("failed to set pids.max: {}", e)))?;
        Ok(())
    }

    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()> {
        let path = self.instance_path(instance_id);
        let max_value = Self::cpu_max_value(limit_usec)?;
        fs::write(path.join("cpu.max"), &max_value)
            .map_err(|e| IsolateError::Cgroup(format!("failed to set cpu.max: {}", e)))?;

        let weight = Self::cpu_weight_from_shares(limit_usec).to_string();
        if let Err(err) = fs::write(path.join("cpu.weight"), weight) {
            if self.strict_mode {
                return Err(IsolateError::Cgroup(format!(
                    "failed to set cpu.weight: {}",
                    err
                )));
            }
            log::warn!("failed to set cpu.weight in permissive mode: {}", err);
        }

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
        let path = self.instance_path(instance_id);

        let memory_limit = match Self::read_optional_limit(&path.join("memory.max"), "memory.max") {
            Ok(value) => value,
            Err(err) if self.strict_mode => return Err(err),
            Err(err) => {
                log::warn!(
                    "failed collecting memory.max limit in permissive mode: {}",
                    err
                );
                None
            }
        };
        let process_limit_raw = match Self::read_optional_limit(&path.join("pids.max"), "pids.max")
        {
            Ok(value) => value,
            Err(err) if self.strict_mode => return Err(err),
            Err(err) => {
                log::warn!(
                    "failed collecting pids.max limit in permissive mode: {}",
                    err
                );
                None
            }
        };
        let process_limit = self.convert_optional_u32_limit("pids.max", process_limit_raw)?;

        let (oom_events, oom_kill_events) = match self.check_oom_events_internal(instance_id) {
            Ok(values) => values,
            Err(err) if self.strict_mode => return Err(err),
            Err(err) => {
                log::warn!(
                    "failed collecting memory.events in permissive mode: {}",
                    err
                );
                (0, 0)
            }
        };
        let memory_peak = self.collect_optional_metric(
            "memory.peak/memory.current",
            self.get_peak_memory_internal(instance_id),
        )?;
        let cpu_usage_usec = self.collect_optional_metric(
            "cpu.stat usage_usec",
            self.read_cpu_usage_internal(instance_id),
        )?;
        let process_count = self.collect_optional_metric(
            "pids.current/cgroup.procs",
            self.read_process_count_internal(instance_id),
        )?;

        Ok(CgroupEvidence {
            memory_peak,
            memory_limit,
            oom_events,
            oom_kill_events,
            cpu_usage_usec,
            process_count,
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
    fn cgroup_v2_creation_works() {
        let cgroup = CgroupV2::with_base_path("/tmp/test_cgroup_v2", "test_instance", false);
        assert!(cgroup.is_ok());
    }

    #[test]
    fn instance_path_sanitizes_slashes() {
        let cgroup = CgroupV2::with_base_path("/tmp/test_cgroup_v2", "rustbox/42", false).unwrap();
        assert_eq!(
            cgroup.instance_path("rustbox/42"),
            PathBuf::from("/tmp/test_cgroup_v2/rustbox_42")
        );
    }

    #[test]
    fn cpu_max_value_rejects_zero() {
        assert!(CgroupV2::cpu_max_value(0).is_err());
    }

    #[test]
    fn cpu_max_value_uses_input_limit() {
        assert_eq!(CgroupV2::cpu_max_value(50_000).unwrap(), "50000 100000");
        assert_eq!(CgroupV2::cpu_max_value(500).unwrap(), "1000 100000");
    }

    #[test]
    fn memory_events_parse_error_is_reported() {
        let root = std::env::temp_dir().join(format!(
            "rustbox-cgroup-v2-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let cgroup = CgroupV2::with_base_path(root.to_str().unwrap(), "instance", false).unwrap();
        let instance_path = cgroup.instance_path("instance");
        std::fs::create_dir_all(&instance_path).unwrap();
        std::fs::write(
            instance_path.join("memory.events"),
            "oom nope\noom_kill 0\n",
        )
        .unwrap();

        assert!(cgroup.check_oom_events_internal("instance").is_err());

        let _ = std::fs::remove_dir_all(&root);
    }
}
