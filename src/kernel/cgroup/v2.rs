/// Cgroup v2 backend implementation
/// Implements P1-CGROUP2-001: v2 OOM Semantics and memory.oom.group
/// Implements P1-CGROUP2-002: v2 Peak Memory Accounting
/// Per plan.md Section 8.3: v2 Required Semantics

use crate::kernel::cgroup::backend::CgroupBackend;
use crate::config::types::{IsolateError, Result, CgroupEvidence};
use std::fs;
use std::path::{PathBuf};

/// Cgroup v2 backend
pub struct CgroupV2 {
    base_path: PathBuf,
    strict_mode: bool,
}

impl CgroupV2 {
    /// Create new cgroup v2 backend
    pub fn new(base_path: &str, strict_mode: bool) -> Result<Self> {
        let base = if base_path.is_empty() {
            PathBuf::from("/sys/fs/cgroup/rustbox")
        } else {
            PathBuf::from(base_path)
        };
        
        Ok(CgroupV2 {
            base_path: base,
            strict_mode,
        })
    }
    
    /// Get cgroup path for instance
    fn instance_path(&self, instance_id: &str) -> PathBuf {
        self.base_path.join(instance_id)
    }
    
    /// Read memory.peak (kernel 5.19+) with fallback to memory.current
    fn get_peak_memory_internal(&self, instance_id: &str) -> Result<u64> {
        let path = self.instance_path(instance_id);
        let peak_path = path.join("memory.peak");
        
        // Try memory.peak first (kernel 5.19+)
        if peak_path.exists() {
            let content = fs::read_to_string(&peak_path)
                .map_err(|e| IsolateError::Cgroup(format!("Failed to read memory.peak: {}", e)))?;
            
            let peak = content.trim().parse::<u64>()
                .map_err(|e| IsolateError::Cgroup(format!("Failed to parse memory.peak: {}", e)))?;
            
            return Ok(peak);
        }
        
        // Fallback to memory.current for older kernels
        let current_path = path.join("memory.current");
        let content = fs::read_to_string(&current_path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read memory.current: {}", e)))?;
        
        let current = content.trim().parse::<u64>()
            .map_err(|e| IsolateError::Cgroup(format!("Failed to parse memory.current: {}", e)))?;
        
        Ok(current)
    }
    
    /// Parse memory.events for OOM detection
    /// Returns (oom_count, oom_kill_count)
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
                    "oom" => {
                        oom_count = parts[1].parse::<u64>().unwrap_or(0);
                    }
                    "oom_kill" => {
                        oom_kill_count = parts[1].parse::<u64>().unwrap_or(0);
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
        
        // Create cgroup directory
        fs::create_dir_all(&path)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to create cgroup: {}", e)))?;
        
        // Set memory.oom.group=1 in strict mode (when supported)
        let oom_group_path = path.join("memory.oom.group");
        if oom_group_path.exists() {
            if let Err(e) = fs::write(&oom_group_path, "1") {
                if self.strict_mode {
                    return Err(IsolateError::Cgroup(format!("Failed to set memory.oom.group: {}", e)));
                } else {
                    log::warn!("Failed to set memory.oom.group (permissive mode): {}", e);
                }
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
        
        fs::write(&procs_path, pid.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to attach process to cgroup: {}", e)))?;
        
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
        
        fs::write(&limit_path, limit.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set process limit: {}", e)))?;
        
        Ok(())
    }
    
    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()> {
        let path = self.instance_path(instance_id);
        
        // Convert microseconds to weight (v2 uses cpu.weight instead of cpu.shares)
        // Default weight is 100, range is 1-10000
        // For now, use a simple conversion
        let weight = (limit_usec / 1000).clamp(1, 10000);
        
        let weight_path = path.join("cpu.weight");
        fs::write(&weight_path, weight.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set CPU weight: {}", e)))?;
        
        Ok(())
    }
    
    fn get_memory_usage(&self) -> Result<u64> {
        // This requires instance_id but trait doesn't provide it
        // For now, return 0 - this will be fixed when we refactor the trait
        Ok(0)
    }
    
    fn get_memory_peak(&self) -> Result<u64> {
        // This requires instance_id but trait doesn't provide it
        // For now, return 0 - this will be fixed when we refactor the trait
        Ok(0)
    }
    
    fn get_cpu_usage(&self) -> Result<u64> {
        // This requires instance_id but trait doesn't provide it
        // For now, return 0 - this will be fixed when we refactor the trait
        Ok(0)
    }
    
    fn get_process_count(&self) -> Result<u32> {
        // This requires instance_id but trait doesn't provide it
        // For now, return 0 - this will be fixed when we refactor the trait
        Ok(0)
    }
    
    fn check_oom(&self) -> Result<bool> {
        // This requires instance_id but trait doesn't provide it
        // For now, return false - this will be fixed when we refactor the trait
        Ok(false)
    }
    
    fn get_oom_kill_count(&self) -> Result<u64> {
        // This requires instance_id but trait doesn't provide it
        // For now, return 0 - this will be fixed when we refactor the trait
        Ok(0)
    }
    
    fn collect_evidence(&self, instance_id: &str) -> Result<CgroupEvidence> {
        let (oom_count, oom_kill_count) = self.check_oom_events_internal(instance_id)?;
        
        Ok(CgroupEvidence {
            memory_peak: Some(self.get_peak_memory_internal(instance_id).unwrap_or(0)),
            memory_limit: None, // TODO: Read from memory.max
            oom_events: oom_count,
            oom_kill_events: oom_kill_count,
            cpu_usage_usec: None, // TODO: Read from cpu.stat
            process_count: None, // TODO: Read from cgroup.procs
            process_limit: None, // TODO: Read from pids.max
        })
    }
    
    fn get_cgroup_path(&self, instance_id: &str) -> PathBuf {
        self.instance_path(instance_id)
    }
    
    fn is_empty(&self) -> Result<bool> {
        // This requires instance_id but trait doesn't provide it
        // For now, return true - this will be fixed when we refactor the trait
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_v2_creation() {
        let cgroup = CgroupV2::new("/tmp/test_cgroup_v2", false);
        assert!(cgroup.is_ok());
    }

    #[test]
    fn test_instance_path() {
        let cgroup = CgroupV2::new("/tmp/test_cgroup_v2", false).unwrap();
        let path = cgroup.instance_path("test_instance");
        assert_eq!(path, PathBuf::from("/tmp/test_cgroup_v2/test_instance"));
    }
}
