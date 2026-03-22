use crate::config::types::{IsolateError, Result};
use log::{error, info};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BaselineChecker {
    baseline_mounts: Vec<String>,
    baseline_cgroups: Vec<PathBuf>,
    baseline_processes: Vec<u32>,
}

impl BaselineChecker {
    pub fn capture_baseline() -> Result<Self> {
        Ok(Self {
            baseline_mounts: Self::get_mounts()?,
            baseline_cgroups: Self::get_cgroups()?,
            baseline_processes: Self::get_processes()?,
        })
    }

    pub fn verify_baseline(&self) -> Result<()> {
        let current_mounts = Self::get_mounts()?;
        let current_cgroups = Self::get_cgroups()?;
        let current_processes = Self::get_processes()?;

        let mut violations = Vec::new();

        for mount in &current_mounts {
            if !self.baseline_mounts.contains(mount) {
                violations.push(format!("Additional mount: {}", mount));
            }
        }

        for cgroup in &current_cgroups {
            if !self.baseline_cgroups.contains(cgroup) {
                violations.push(format!("Additional cgroup: {}", cgroup.display()));
            }
        }

        for pid in &current_processes {
            if !self.baseline_processes.contains(pid) && Self::is_sandbox_process(*pid) {
                violations.push(format!("Leaked sandbox process: {}", pid));
            }
        }

        if !violations.is_empty() {
            error!("Baseline violations detected: {:?}", violations);
            return Err(IsolateError::Config(format!(
                "Host-clean baseline violated: {} issues",
                violations.len()
            )));
        }

        info!("Baseline verification passed");
        Ok(())
    }

    fn get_mounts() -> Result<Vec<String>> {
        let content = fs::read_to_string("/proc/mounts").map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read /proc/mounts: {}", e),
            ))
        })?;
        Ok(content.lines().map(|s| s.to_string()).collect())
    }

    fn get_cgroups() -> Result<Vec<PathBuf>> {
        let mut cgroups = Vec::new();
        let cgroup_base = Path::new("/sys/fs/cgroup");
        if cgroup_base.exists() {
            for controller in &["memory", "cpu", "cpuacct", "pids"] {
                let controller_path = cgroup_base.join(controller);
                if controller_path.exists() {
                    if let Ok(entries) = fs::read_dir(&controller_path) {
                        for entry in entries.flatten() {
                            if entry.path().is_dir() {
                                cgroups.push(entry.path());
                            }
                        }
                    }
                }
            }
        }
        Ok(cgroups)
    }

    fn get_processes() -> Result<Vec<u32>> {
        let mut processes = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if let Ok(pid) = file_name.parse::<u32>() {
                        processes.push(pid);
                    }
                }
            }
        }
        Ok(processes)
    }

    fn is_sandbox_process(pid: u32) -> bool {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            return cmdline.contains("rustbox");
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_checker() {
        let baseline = BaselineChecker::capture_baseline();
        assert!(baseline.is_ok());
    }
}
