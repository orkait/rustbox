/// Cleanup and resource management
/// Implements P0-CLEAN-001: Idempotent Cleanup Under Retry
/// Implements P0-CLEAN-002: Failure-Injection Matrix (partial)
/// Implements P0-CLEAN-003: Cleanup Failure Escalation
/// Per plan.md Section 5.1: Failure-Path Discipline Contract
use crate::config::types::{IsolateError, Result};
use crate::safety::safe_cleanup;
use log::{debug, error, info, warn};
use std::fs;
use std::path::{Path, PathBuf};

/// Resource types that need cleanup
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Mount,
    Cgroup,
    Process,
    FileDescriptor,
    TempDirectory,
    Workspace,
}

/// Resource ledger entry
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub resource_type: ResourceType,
    pub identifier: String,
    pub path: Option<PathBuf>,
    pub created_at: std::time::SystemTime,
}

/// Resource ledger for tracking created resources
/// Per plan.md: Resources recorded immediately after successful creation
pub struct ResourceLedger {
    entries: Vec<ResourceEntry>,
}

impl ResourceLedger {
    /// Create new empty ledger
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record resource creation
    /// Must be called immediately after successful creation
    pub fn record(
        &mut self,
        resource_type: ResourceType,
        identifier: String,
        path: Option<PathBuf>,
    ) {
        let entry = ResourceEntry {
            resource_type,
            identifier,
            path,
            created_at: std::time::SystemTime::now(),
        };

        debug!("Recording resource: {:?}", entry);
        self.entries.push(entry);
    }

    /// Get all entries of a specific type
    pub fn get_by_type(&self, resource_type: &ResourceType) -> Vec<&ResourceEntry> {
        self.entries
            .iter()
            .filter(|e| &e.resource_type == resource_type)
            .collect()
    }

    /// Get all entries in reverse creation order (for cleanup)
    pub fn reverse_order(&self) -> Vec<&ResourceEntry> {
        self.entries.iter().rev().collect()
    }

    /// Remove entry after successful cleanup
    pub fn remove(&mut self, identifier: &str) {
        self.entries.retain(|e| e.identifier != identifier);
    }

    /// Check if ledger is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get count of resources
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

/// Cleanup manager with idempotent operations
/// Per plan.md: Cleanup is safe to call repeatedly after partial failure
pub struct CleanupManager {
    ledger: ResourceLedger,
    cleanup_errors: Vec<String>,
}

impl CleanupManager {
    /// Create new cleanup manager
    pub fn new() -> Self {
        Self {
            ledger: ResourceLedger::new(),
            cleanup_errors: Vec::new(),
        }
    }

    /// Record resource for cleanup
    pub fn record_resource(
        &mut self,
        resource_type: ResourceType,
        identifier: String,
        path: Option<PathBuf>,
    ) {
        self.ledger.record(resource_type, identifier, path);
    }

    /// Cleanup all resources in reverse creation order
    /// Idempotent: safe to call multiple times
    pub fn cleanup_all(&mut self) -> Result<()> {
        info!("Starting cleanup of {} resources", self.ledger.count());

        let entries = self.ledger.reverse_order();
        let mut failed_cleanups = Vec::new();

        for entry in entries {
            match self.cleanup_resource(entry) {
                Ok(()) => {
                    debug!("Successfully cleaned up: {}", entry.identifier);
                }
                Err(e) => {
                    let error_msg = format!("Failed to cleanup {}: {}", entry.identifier, e);
                    warn!("{}", error_msg);
                    self.cleanup_errors.push(error_msg.clone());
                    failed_cleanups.push(entry.identifier.clone());
                }
            }
        }

        if !failed_cleanups.is_empty() {
            return Err(IsolateError::Config(format!(
                "Cleanup failed for {} resources: {:?}",
                failed_cleanups.len(),
                failed_cleanups
            )));
        }

        info!("Cleanup complete");
        Ok(())
    }

    /// Cleanup a single resource (idempotent)
    fn cleanup_resource(&self, entry: &ResourceEntry) -> Result<()> {
        match entry.resource_type {
            ResourceType::Mount => self.cleanup_mount(entry),
            ResourceType::Cgroup => self.cleanup_cgroup(entry),
            ResourceType::Process => self.cleanup_process(entry),
            ResourceType::FileDescriptor => self.cleanup_fd(entry),
            ResourceType::TempDirectory => self.cleanup_temp_dir(entry),
            ResourceType::Workspace => self.cleanup_workspace(entry),
        }
    }

    /// Cleanup mount (idempotent)
    fn cleanup_mount(&self, entry: &ResourceEntry) -> Result<()> {
        if let Some(path) = &entry.path {
            // Check if still mounted
            if Self::is_mounted(path)? {
                debug!("Unmounting: {}", path.display());
                Self::unmount(path)?;
            } else {
                debug!("Mount already cleaned: {}", path.display());
            }
        }
        Ok(())
    }

    /// Cleanup cgroup (idempotent)
    fn cleanup_cgroup(&self, entry: &ResourceEntry) -> Result<()> {
        if let Some(path) = &entry.path {
            if path.exists() {
                // Check if empty first
                if Self::is_cgroup_empty(path)? {
                    debug!("Removing cgroup: {}", path.display());
                    fs::remove_dir(path).map_err(|e| {
                        IsolateError::Cgroup(format!(
                            "Failed to remove cgroup {}: {}",
                            path.display(),
                            e
                        ))
                    })?;
                } else {
                    warn!("Cgroup not empty, cannot remove: {}", path.display());
                    return Err(IsolateError::Cgroup(format!(
                        "Cgroup not empty: {}",
                        path.display()
                    )));
                }
            } else {
                debug!("Cgroup already cleaned: {}", path.display());
            }
        }
        Ok(())
    }

    /// Cleanup process (idempotent)
    fn cleanup_process(&self, entry: &ResourceEntry) -> Result<()> {
        let pid: u32 = entry
            .identifier
            .parse()
            .map_err(|_| IsolateError::Process(format!("Invalid PID: {}", entry.identifier)))?;

        // Check if process still exists
        if Self::is_process_alive(pid) {
            debug!("Killing process: {}", pid);
            Self::kill_process(pid)?;
        } else {
            debug!("Process already terminated: {}", pid);
        }

        Ok(())
    }

    /// Cleanup file descriptor (idempotent)
    fn cleanup_fd(&self, entry: &ResourceEntry) -> Result<()> {
        // FDs are automatically closed when dropped in Rust
        // This is a no-op but kept for ledger completeness
        debug!("FD cleanup (no-op): {}", entry.identifier);
        Ok(())
    }

    /// Cleanup temporary directory (idempotent)
    fn cleanup_temp_dir(&self, entry: &ResourceEntry) -> Result<()> {
        if let Some(path) = &entry.path {
            if path.exists() {
                debug!("Removing temp directory: {}", path.display());
                safe_cleanup::remove_tree_secure(path).map_err(|e| {
                    IsolateError::Filesystem(format!(
                        "Failed to remove temp directory {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            } else {
                debug!("Temp directory already cleaned: {}", path.display());
            }
        }
        Ok(())
    }

    /// Cleanup workspace (idempotent)
    fn cleanup_workspace(&self, entry: &ResourceEntry) -> Result<()> {
        if let Some(path) = &entry.path {
            if path.exists() {
                debug!("Removing workspace: {}", path.display());
                safe_cleanup::remove_tree_secure(path).map_err(|e| {
                    IsolateError::Filesystem(format!(
                        "Failed to remove workspace {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            } else {
                debug!("Workspace already cleaned: {}", path.display());
            }
        }
        Ok(())
    }

    /// Check if path is mounted
    fn is_mounted(path: &Path) -> Result<bool> {
        // Read /proc/mounts to check if path is mounted
        let mounts = fs::read_to_string("/proc/mounts").map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read /proc/mounts: {}", e),
            ))
        })?;

        let path_str = path.to_string_lossy();
        Ok(mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == path_str
        }))
    }

    /// Unmount path
    fn unmount(path: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::mount::umount;
            umount(path).map_err(|e| {
                IsolateError::Config(format!("Failed to unmount {}: {}", path.display(), e))
            })?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            return Err(IsolateError::Config(
                "Unmount not supported on this platform".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if cgroup is empty
    fn is_cgroup_empty(path: &Path) -> Result<bool> {
        let procs_file = path.join("cgroup.procs");
        if !procs_file.exists() {
            // Try tasks file (cgroup v1)
            let tasks_file = path.join("tasks");
            if !tasks_file.exists() {
                return Ok(true); // Assume empty if neither file exists
            }

            let content = fs::read_to_string(&tasks_file)
                .map_err(|e| IsolateError::Cgroup(format!("Failed to read tasks file: {}", e)))?;
            return Ok(content.trim().is_empty());
        }

        let content = fs::read_to_string(&procs_file)
            .map_err(|e| IsolateError::Cgroup(format!("Failed to read cgroup.procs: {}", e)))?;

        Ok(content.trim().is_empty())
    }

    /// Check if process is alive
    fn is_process_alive(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    /// Kill process
    fn kill_process(pid: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            signal::kill(pid, Signal::SIGKILL).map_err(|e| {
                IsolateError::Process(format!("Failed to kill process {}: {}", pid, e))
            })?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            return Err(IsolateError::Process(
                "Process kill not supported on this platform".to_string(),
            ));
        }

        Ok(())
    }

    /// Get cleanup errors
    pub fn get_errors(&self) -> &[String] {
        &self.cleanup_errors
    }

    /// Check if cleanup had errors
    pub fn has_errors(&self) -> bool {
        !self.cleanup_errors.is_empty()
    }
}

/// Host-clean baseline checker
/// Per plan.md Section 5.1: Host-clean baseline equivalence
pub struct BaselineChecker {
    baseline_mounts: Vec<String>,
    baseline_cgroups: Vec<PathBuf>,
    baseline_processes: Vec<u32>,
}

impl BaselineChecker {
    /// Capture baseline before execution
    pub fn capture_baseline() -> Result<Self> {
        Ok(Self {
            baseline_mounts: Self::get_mounts()?,
            baseline_cgroups: Self::get_cgroups()?,
            baseline_processes: Self::get_processes()?,
        })
    }

    /// Verify host-clean baseline after cleanup
    pub fn verify_baseline(&self) -> Result<()> {
        let current_mounts = Self::get_mounts()?;
        let current_cgroups = Self::get_cgroups()?;
        let current_processes = Self::get_processes()?;

        let mut violations = Vec::new();

        // Check for additional mounts
        for mount in &current_mounts {
            if !self.baseline_mounts.contains(mount) {
                violations.push(format!("Additional mount: {}", mount));
            }
        }

        // Check for additional cgroups
        for cgroup in &current_cgroups {
            if !self.baseline_cgroups.contains(cgroup) {
                violations.push(format!("Additional cgroup: {}", cgroup.display()));
            }
        }

        // Check for additional processes (sandbox-attributable)
        for pid in &current_processes {
            if !self.baseline_processes.contains(pid) {
                // Check if this is a sandbox-related process
                if Self::is_sandbox_process(*pid) {
                    violations.push(format!("Leaked sandbox process: {}", pid));
                }
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

    /// Get current mounts
    fn get_mounts() -> Result<Vec<String>> {
        let content = fs::read_to_string("/proc/mounts").map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read /proc/mounts: {}", e),
            ))
        })?;

        Ok(content.lines().map(|s| s.to_string()).collect())
    }

    /// Get current cgroups
    fn get_cgroups() -> Result<Vec<PathBuf>> {
        let mut cgroups = Vec::new();

        // Check cgroup v1 controllers
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

    /// Get current processes
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

    /// Check if process is sandbox-related
    fn is_sandbox_process(pid: u32) -> bool {
        // Check if process cmdline contains "rustbox"
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
    fn test_resource_ledger() {
        let mut ledger = ResourceLedger::new();
        assert!(ledger.is_empty());

        ledger.record(
            ResourceType::TempDirectory,
            "temp1".to_string(),
            Some(PathBuf::from("/tmp/test")),
        );

        assert_eq!(ledger.count(), 1);
        assert!(!ledger.is_empty());

        let entries = ledger.get_by_type(&ResourceType::TempDirectory);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_cleanup_manager_creation() {
        let manager = CleanupManager::new();
        assert!(!manager.has_errors());
    }

    #[test]
    fn test_baseline_checker() {
        let baseline = BaselineChecker::capture_baseline();
        assert!(baseline.is_ok());
    }
}
