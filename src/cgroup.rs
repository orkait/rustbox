/// Enhanced Cgroup management for resource control with improved reliability
use crate::types::{IsolateError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Cgroup {
    name: String,
    cgroup_paths: std::collections::HashMap<String, PathBuf>,
    available_controllers: HashSet<String>,
    has_cgroup_support: bool,
}

impl Cgroup {
    pub fn new(name: &str, strict_mode: bool) -> Result<Self> {
        // Validate and sanitize the name
        if name.is_empty() || name.len() > 255 {
            return Err(IsolateError::Cgroup(
                "Invalid cgroup name length".to_string(),
            ));
        }

        let sanitized_name = name.replace("/", "_").replace("..", "_");
        let cgroup_base = "/sys/fs/cgroup";

        // Initialize paths for all controllers
        let mut cgroup_paths = std::collections::HashMap::new();

        let cgroups_available = Self::cgroups_available();
        if !cgroups_available {
            if strict_mode {
                return Err(IsolateError::Cgroup(
                    "Cgroups not available on this system".to_string(),
                ));
            } else {
                eprintln!("Warning: Cgroups not available. Resource limits will not be enforced.");
                return Ok(Self {
                    name: sanitized_name,
                    cgroup_paths: std::collections::HashMap::new(),
                    available_controllers: HashSet::new(),
                    has_cgroup_support: false,
                });
            }
        }

        let available_controllers = match Self::get_available_controllers() {
            Ok(controllers) => controllers,
            Err(e) => {
                if strict_mode {
                    return Err(IsolateError::Cgroup(format!(
                        "Failed to get available controllers: {}",
                        e
                    )));
                } else {
                    eprintln!("Warning: Failed to get available controllers: {}", e);
                    HashSet::new()
                }
            }
        };

        // Create controller paths and directories
        let controllers_to_use = ["memory", "cpu", "cpuacct", "pids"];
        let mut creation_errors = Vec::new();

        for controller in &controllers_to_use {
            if available_controllers.contains(*controller) {
                let controller_path = Path::new(cgroup_base)
                    .join(controller)
                    .join(&sanitized_name);

                match fs::create_dir_all(&controller_path) {
                    Ok(_) => {
                        cgroup_paths.insert(controller.to_string(), controller_path);
                    }
                    Err(e) => {
                        creation_errors.push(format!("{}: {}", controller, e));
                    }
                }
            }
        }

        if strict_mode {
            let required_controllers = vec!["memory", "cpu", "cpuacct"];
            for controller in &required_controllers {
                if !available_controllers.contains(*controller) {
                    return Err(IsolateError::Cgroup(format!(
                        "Required controller '{}' not available. Available controllers: {:?}",
                        controller, available_controllers
                    )));
                }
                if !cgroup_paths.contains_key(*controller) {
                    return Err(IsolateError::Cgroup(format!(
                        "Failed to create cgroup for controller '{}'. Errors: {:?}",
                        controller, creation_errors
                    )));
                }
            }
        }

        if !creation_errors.is_empty() && cgroup_paths.is_empty() {
            if strict_mode {
                return Err(IsolateError::Cgroup(format!(
                    "Failed to create any cgroup directories. Errors: {:?}",
                    creation_errors
                )));
            } else {
                eprintln!(
                    "Warning: Failed to create cgroup directories: {:?}",
                    creation_errors
                );
                return Ok(Self {
                    name: sanitized_name,
                    cgroup_paths: std::collections::HashMap::new(),
                    available_controllers,
                    has_cgroup_support: false,
                });
            }
        }

        Ok(Self {
            name: sanitized_name.clone(),
            cgroup_paths,
            available_controllers,
            has_cgroup_support: true,
        })
    }

    /// Validate memory limit value
    fn validate_memory_limit(limit_bytes: u64) -> Result<()> {
        if limit_bytes == 0 {
            return Err(IsolateError::Cgroup(
                "Memory limit cannot be zero".to_string(),
            ));
        }
        if limit_bytes < 1024 * 1024 {
            // 1MB minimum
            return Err(IsolateError::Cgroup(
                "Memory limit too small (minimum 1MB)".to_string(),
            ));
        }
        if limit_bytes > (1u64 << 50) {
            // 1PB maximum (reasonable upper bound)
            return Err(IsolateError::Cgroup("Memory limit too large".to_string()));
        }
        Ok(())
    }

    pub fn set_memory_limit(&self, limit_bytes: u64) -> Result<()> {
        if !self.has_cgroup_support || !self.available_controllers.contains("memory") {
            return Ok(());
        }

        Self::validate_memory_limit(limit_bytes)?;

        let memory_path = self.cgroup_paths.get("memory").ok_or_else(|| {
            IsolateError::Cgroup("Memory controller path not available".to_string())
        })?;

        // Set memory limit
        let limit_file = memory_path.join("memory.limit_in_bytes");
        fs::write(&limit_file, limit_bytes.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set memory limit: {}", e)))?;

        // Set memory+swap limit (if available) - this is critical for security
        let memsw_file = memory_path.join("memory.memsw.limit_in_bytes");
        if memsw_file.exists() {
            fs::write(&memsw_file, limit_bytes.to_string()).map_err(|e| {
                IsolateError::Cgroup(format!("Failed to set memory+swap limit: {}", e))
            })?;
        }

        // Disable swap accounting if available (for better predictability)
        let swappiness_file = memory_path.join("memory.swappiness");
        if swappiness_file.exists() {
            let _ = fs::write(&swappiness_file, "0");
        }

        Ok(())
    }

    pub fn set_cpu_limit(&self, cpu_shares: u64) -> Result<()> {
        if !self.has_cgroup_support || !self.available_controllers.contains("cpu") {
            return Ok(());
        }

        // Validate CPU shares (standard range is 2-262144)
        if cpu_shares < 2 || cpu_shares > 262144 {
            return Err(IsolateError::Cgroup(format!(
                "Invalid CPU shares: {} (must be between 2 and 262144)",
                cpu_shares
            )));
        }

        let cpu_path = self
            .cgroup_paths
            .get("cpu")
            .ok_or_else(|| IsolateError::Cgroup("CPU controller path not available".to_string()))?;

        // Set CPU shares
        let shares_file = cpu_path.join("cpu.shares");
        fs::write(&shares_file, cpu_shares.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set CPU shares: {}", e)))?;

        Ok(())
    }

    pub fn set_process_limit(&self, limit: u64) -> Result<()> {
        if !self.has_cgroup_support || !self.available_controllers.contains("pids") {
            return Ok(());
        }

        // Validate process limit
        if limit == 0 {
            return Err(IsolateError::Cgroup(
                "Process limit cannot be zero".to_string(),
            ));
        }
        if limit > 32768 {
            // Reasonable upper bound
            return Err(IsolateError::Cgroup(
                "Process limit too high (maximum 32768)".to_string(),
            ));
        }

        let pids_path = self.cgroup_paths.get("pids").ok_or_else(|| {
            IsolateError::Cgroup("PIDs controller path not available".to_string())
        })?;

        let max_file = pids_path.join("pids.max");
        fs::write(&max_file, limit.to_string())
            .map_err(|e| IsolateError::Cgroup(format!("Failed to set process limit: {}", e)))?;

        Ok(())
    }

    /// Validate PID exists and is accessible
    fn validate_pid(pid: u32) -> Result<()> {
        if pid == 0 {
            return Err(IsolateError::Cgroup("Invalid PID: 0".to_string()));
        }

        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return Err(IsolateError::Cgroup(format!(
                "Process {} does not exist",
                pid
            )));
        }

        Ok(())
    }

    pub fn add_process(&self, pid: u32) -> Result<()> {
        if !self.has_cgroup_support {
            return Ok(());
        }

        Self::validate_pid(pid)?;
        let pid_str = pid.to_string();
        let mut errors = Vec::new();
        let mut successful_controllers = Vec::new();

        // Try to add process to all available controllers atomically
        let controllers = ["memory", "cpu", "cpuacct", "pids"];

        for controller in &controllers {
            if let Some(controller_path) = self.cgroup_paths.get(*controller) {
                let tasks_file = controller_path.join("tasks");
                match fs::write(&tasks_file, &pid_str) {
                    Ok(_) => successful_controllers.push(*controller),
                    Err(e) => errors.push(format!("{}: {}", controller, e)),
                }
            }
        }

        // If any critical controller failed, this is an error
        let critical_controllers = ["memory", "cpu"];
        let failed_critical = critical_controllers.iter().any(|c| {
            self.available_controllers.contains(*c) && !successful_controllers.contains(c)
        });

        if failed_critical {
            return Err(IsolateError::Cgroup(format!(
                "Failed to add process {} to critical cgroups. Errors: {:?}",
                pid, errors
            )));
        }

        if !errors.is_empty() {
            log::warn!(
                "Some non-critical cgroup operations failed for PID {}: {:?}",
                pid,
                errors
            );
        }

        Ok(())
    }

    pub fn get_peak_memory_usage(&self) -> Result<u64> {
        if !self.has_cgroup_support || !self.available_controllers.contains("memory") {
            return Ok(0);
        }

        let memory_path = self.cgroup_paths.get("memory").ok_or_else(|| {
            IsolateError::Cgroup("Memory controller path not available".to_string())
        })?;

        let usage_file = memory_path.join("memory.max_usage_in_bytes");
        let usage_content = fs::read_to_string(&usage_file).map_err(|e| {
            IsolateError::Cgroup(format!("Failed to read peak memory usage: {}", e))
        })?;

        usage_content
            .trim()
            .parse()
            .map_err(|e| IsolateError::Cgroup(format!("Failed to parse peak memory usage: {}", e)))
    }

    /// Get current memory usage (more reliable than peak for live monitoring)
    pub fn get_current_memory_usage(&self) -> Result<u64> {
        if !self.has_cgroup_support || !self.available_controllers.contains("memory") {
            return Ok(0);
        }

        let memory_path = self.cgroup_paths.get("memory").ok_or_else(|| {
            IsolateError::Cgroup("Memory controller path not available".to_string())
        })?;

        let usage_file = memory_path.join("memory.usage_in_bytes");
        let usage_content = fs::read_to_string(&usage_file).map_err(|e| {
            IsolateError::Cgroup(format!("Failed to read current memory usage: {}", e))
        })?;

        usage_content.trim().parse().map_err(|e| {
            IsolateError::Cgroup(format!("Failed to parse current memory usage: {}", e))
        })
    }

    /// Get comprehensive memory statistics from cgroup
    pub fn get_memory_stats(&self) -> Result<(u64, u64, u64)> {
        if !self.has_cgroup_support || !self.available_controllers.contains("memory") {
            return Ok((0, 0, 0));
        }

        let current = self.get_current_memory_usage().unwrap_or(0);
        let peak = self.get_peak_memory_usage().unwrap_or(0);

        // Try to get memory limit
        let memory_path = self.cgroup_paths.get("memory").ok_or_else(|| {
            IsolateError::Cgroup("Memory controller path not available".to_string())
        })?;

        let limit_file = memory_path.join("memory.limit_in_bytes");
        let limit = fs::read_to_string(&limit_file)
            .and_then(|s| {
                s.trim()
                    .parse::<u64>()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
            .unwrap_or(u64::MAX);

        Ok((current, peak, limit))
    }

    /// Check if the process hit the memory limit (OOM condition)
    pub fn check_oom_killed(&self) -> bool {
        if !self.has_cgroup_support || !self.available_controllers.contains("memory") {
            return false;
        }

        let memory_path = match self.cgroup_paths.get("memory") {
            Some(path) => path,
            None => return false,
        };

        // Check memory.oom_control for under_oom flag
        let oom_control_file = memory_path.join("memory.oom_control");
        if let Ok(oom_control) = fs::read_to_string(&oom_control_file) {
            if oom_control.contains("under_oom 1") {
                return true;
            }
        }

        // Also check memory.stat for oom_kill events
        let memory_stat_file = memory_path.join("memory.stat");
        if let Ok(memory_stat) = fs::read_to_string(&memory_stat_file) {
            for line in memory_stat.lines() {
                if line.starts_with("oom_kill ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(count) = parts[1].parse::<u64>() {
                            if count > 0 {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check if current memory usage equals the limit (potential OOM)
        let limit_file = memory_path.join("memory.limit_in_bytes");
        let usage_file = memory_path.join("memory.usage_in_bytes");

        if let (Ok(limit_content), Ok(usage_content)) = (
            fs::read_to_string(&limit_file),
            fs::read_to_string(&usage_file),
        ) {
            if let (Ok(limit), Ok(usage)) = (
                limit_content.trim().parse::<u64>(),
                usage_content.trim().parse::<u64>(),
            ) {
                // If usage is very close to limit (within 1MB or 95% of limit), consider it OOM
                let threshold = std::cmp::min(1024 * 1024, limit / 20); // 1MB or 5% of limit
                if limit > 0 && usage >= limit.saturating_sub(threshold) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_cpu_usage(&self) -> Result<f64> {
        if !self.has_cgroup_support || !self.available_controllers.contains("cpuacct") {
            return Ok(0.0);
        }

        // Method 1: Try cpuacct.usage (nanoseconds, most accurate)
        let cpuacct_usage_path = Path::new("/sys/fs/cgroup/cpuacct")
            .join(&self.name)
            .join("cpuacct.usage");

        if cpuacct_usage_path.exists() {
            if let Ok(usage_content) = fs::read_to_string(&cpuacct_usage_path) {
                if let Ok(usage_ns) = usage_content.trim().parse::<u64>() {
                    let cpu_time = usage_ns as f64 / 1_000_000_000.0;
                    return Ok(cpu_time);
                }
            }
        }

        // Method 2: Try cpuacct.stat (USER_HZ units, fallback)
        let cpuacct_stat_path = Path::new("/sys/fs/cgroup/cpuacct")
            .join(&self.name)
            .join("cpuacct.stat");

        if cpuacct_stat_path.exists() {
            if let Ok(stat_content) = fs::read_to_string(&cpuacct_stat_path) {
                let mut user_time = 0u64;
                let mut sys_time = 0u64;

                for line in stat_content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        match parts[0] {
                            "user" => {
                                user_time = parts[1].parse().unwrap_or(0);
                            }
                            "system" => {
                                sys_time = parts[1].parse().unwrap_or(0);
                            }
                            _ => {}
                        }
                    }
                }

                if user_time > 0 || sys_time > 0 {
                    let total_time = user_time + sys_time;
                    // Convert USER_HZ to seconds (typically USER_HZ = 100)
                    let cpu_time = total_time as f64 / 100.0;
                    return Ok(cpu_time);
                }
            }
        }

        Ok(0.0)
    }

    /// Get comprehensive resource usage statistics from cgroups exclusively
    pub fn get_resource_stats(&self) -> (f64, u64, bool) {
        let cpu_time = self.get_cpu_usage().unwrap_or(0.0);
        let memory_peak = self.get_peak_memory_usage().unwrap_or(0);
        let oom_killed = self.check_oom_killed();

        (cpu_time, memory_peak, oom_killed)
    }

    /// Check if cgroup is in a resource limit violation state
    pub fn is_resource_limited(&self) -> (bool, bool) {
        let oom_killed = self.check_oom_killed();

        // Check if memory usage is at or near limit
        let memory_limited = if let Ok(current) = self.get_current_memory_usage() {
            if let Some(memory_path) = self.cgroup_paths.get("memory") {
                let limit_file = memory_path.join("memory.limit_in_bytes");
                if let Ok(limit_content) = fs::read_to_string(&limit_file) {
                    if let Ok(limit) = limit_content.trim().parse::<u64>() {
                        let threshold = std::cmp::min(1024 * 1024, limit / 20); // 1MB or 5% of limit
                        limit > 0 && current >= limit.saturating_sub(threshold)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        (oom_killed || memory_limited, false) // (memory_limited, cpu_limited)
    }

    pub fn cleanup(&self) -> Result<()> {
        if !self.has_cgroup_support {
            return Ok(());
        }

        let mut cleanup_errors = Vec::new();

        // First, try to move any remaining processes out of the cgroups
        for (controller, path) in &self.cgroup_paths {
            let tasks_file = path.join("tasks");
            if tasks_file.exists() {
                if let Ok(tasks_content) = fs::read_to_string(&tasks_file) {
                    for line in tasks_content.lines() {
                        if let Ok(pid) = line.trim().parse::<u32>() {
                            // Try to move process back to root cgroup
                            let root_tasks =
                                Path::new("/sys/fs/cgroup").join(controller).join("tasks");
                            let _ = fs::write(&root_tasks, pid.to_string());
                        }
                    }
                }
            }
        }

        // Now remove the cgroup directories
        for (controller, path) in &self.cgroup_paths {
            if path.exists() {
                match fs::remove_dir(path) {
                    Ok(_) => {}
                    Err(e) => {
                        cleanup_errors.push(format!("{}: {}", controller, e));
                    }
                }
            }
        }

        if !cleanup_errors.is_empty() {
            log::warn!(
                "Some cgroup cleanup operations failed: {:?}",
                cleanup_errors
            );
            // Don't return error for cleanup issues, just log them
        }

        Ok(())
    }

    fn get_available_controllers() -> Result<HashSet<String>> {
        let content = fs::read_to_string("/proc/cgroups")
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read /proc/cgroups: {}", e)))?;

        let mut controllers = HashSet::new();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let controller_name = parts[0];
                let enabled = parts[3] == "1";

                if enabled {
                    controllers.insert(controller_name.to_string());
                }
            }
        }

        Ok(controllers)
    }

    pub fn cgroups_available() -> bool {
        Path::new("/proc/cgroups").exists() && Path::new("/sys/fs/cgroup").exists()
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn cgroups_available() -> bool {
    Cgroup::cgroups_available()
}
