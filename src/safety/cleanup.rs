use crate::config::types::{IsolateError, Result};
use log::{error, info};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BaselineChecker {
    baseline_mounts: Vec<String>,
    baseline_cgroups: Vec<PathBuf>,
}

impl BaselineChecker {
    pub fn capture_baseline() -> Result<Self> {
        Ok(Self {
            baseline_mounts: Self::get_mounts()?,
            baseline_cgroups: Self::get_cgroups()?,
        })
    }

    pub fn verify_baseline(&self) -> Result<()> {
        let current_mounts = Self::get_mounts()?;
        let current_cgroups = Self::get_cgroups()?;

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

        // Process leak detection is intentionally omitted. The supervisor
        // reaps the proxy via child.wait(), and the proxy's PID namespace
        // guarantees all descendants are killed when the namespace leader
        // exits. Scanning /proc is racy and redundant with kernel guarantees.

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
