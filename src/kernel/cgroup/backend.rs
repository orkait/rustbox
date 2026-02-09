/// Cgroup backend abstraction for v1/v2 dual support
/// Implements P1-CGROUP-001: Cgroup Backend Interface
/// Per plan.md Section 8: Resource Governance and Cgroup Policy
use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::path::PathBuf;

/// Cgroup backend trait - common interface for v1 and v2
pub trait CgroupBackend: Send + Sync {
    /// Get backend name
    fn backend_name(&self) -> &str;

    /// Create cgroup for sandbox
    fn create(&self, instance_id: &str) -> Result<()>;

    /// Remove cgroup
    fn remove(&self, instance_id: &str) -> Result<()>;

    /// Attach process to cgroup (must happen before exec)
    fn attach_process(&self, instance_id: &str, pid: u32) -> Result<()>;

    /// Set memory limit
    fn set_memory_limit(&self, instance_id: &str, limit_bytes: u64) -> Result<()>;

    /// Set process limit
    fn set_process_limit(&self, instance_id: &str, limit: u32) -> Result<()>;

    /// Set CPU limit (if supported)
    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()>;

    /// Get memory usage
    fn get_memory_usage(&self) -> Result<u64>;

    /// Get peak memory usage
    fn get_memory_peak(&self) -> Result<u64>;

    /// Get CPU usage in microseconds
    fn get_cpu_usage(&self) -> Result<u64>;

    /// Get process count
    fn get_process_count(&self) -> Result<u32>;

    /// Check if OOM occurred
    fn check_oom(&self) -> Result<bool>;

    /// Get OOM kill count
    fn get_oom_kill_count(&self) -> Result<u64>;

    /// Collect evidence for verdict
    fn collect_evidence(&self, instance_id: &str) -> Result<CgroupEvidence>;

    /// Get cgroup path
    fn get_cgroup_path(&self, instance_id: &str) -> PathBuf;

    /// Check if cgroup is empty (no processes)
    fn is_empty(&self) -> Result<bool>;
}

/// Cgroup backend selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupBackendType {
    V1,
    V2,
}

/// Detect available cgroup backend
pub fn detect_cgroup_backend() -> Option<CgroupBackendType> {
    // Check for cgroup v2 (unified hierarchy)
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Some(CgroupBackendType::V2);
    }

    // Check for cgroup v1
    if std::path::Path::new("/sys/fs/cgroup/memory").exists()
        && std::path::Path::new("/sys/fs/cgroup/cpu").exists()
    {
        return Some(CgroupBackendType::V1);
    }

    None
}

/// Create cgroup backend based on selection policy
/// Per plan.md Section 8.1: Backend Selection
/// - default: cgroup v2
/// - explicit override: --cgroup-v1 forces v1
/// - automatic fallback: if v2 unavailable, use v1
/// - strict-mode rejection: if selected backend cannot enforce mandatory limits
pub fn create_cgroup_backend(
    force_v1: bool,
    strict_mode: bool,
    instance_id: &str,
) -> Result<Box<dyn CgroupBackend>> {
    let detected = detect_cgroup_backend();

    log::info!(
        "Cgroup backend selection: force_v1={}, strict_mode={}, detected={:?}",
        force_v1,
        strict_mode,
        detected
    );

    if force_v1 {
        // Explicit v1 override via --cgroup-v1
        log::info!("Cgroup v1 explicitly requested via --cgroup-v1 flag");

        match detected {
            Some(CgroupBackendType::V1) => {
                log::info!("Using cgroup v1 backend (explicit override)");
                Ok(Box::new(crate::kernel::cgroup::v1::Cgroup::new(
                    instance_id,
                    strict_mode,
                )?))
            }
            Some(CgroupBackendType::V2) => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "Cgroup v1 forced but only v2 available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("Cgroup v1 forced but only v2 available, using v2 anyway");
                    Ok(Box::new(crate::kernel::cgroup::v2::CgroupV2::new(
                        instance_id,
                        false,
                    )?))
                }
            }
            None => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "Cgroup v1 forced but not available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("Cgroup v1 forced but not available, continuing without cgroups");
                    Err(IsolateError::Cgroup(
                        "Cgroup v1 forced but not available".to_string(),
                    ))
                }
            }
        }
    } else {
        // Default: v2 preferred, v1 fallback
        match detected {
            Some(CgroupBackendType::V2) => {
                log::info!("Using cgroup v2 backend (default, v2 detected)");
                Ok(Box::new(crate::kernel::cgroup::v2::CgroupV2::new(
                    instance_id,
                    strict_mode,
                )?))
            }
            Some(CgroupBackendType::V1) => {
                log::info!("Using cgroup v1 backend (fallback, v2 not available)");
                Ok(Box::new(crate::kernel::cgroup::v1::Cgroup::new(
                    instance_id,
                    strict_mode,
                )?))
            }
            None => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "No cgroup backend available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("No cgroup backend available, continuing without resource limits");
                    Err(IsolateError::Cgroup(
                        "No cgroup backend available".to_string(),
                    ))
                }
            }
        }
    }
}

/// Get backend name from detected type
pub fn backend_type_name(backend_type: CgroupBackendType) -> &'static str {
    match backend_type {
        CgroupBackendType::V1 => "cgroup_v1",
        CgroupBackendType::V2 => "cgroup_v2",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cgroup_backend() {
        let backend = detect_cgroup_backend();
        println!("Detected cgroup backend: {:?}", backend);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_backend_selection() {
        // Test with strict mode disabled
        let result = create_cgroup_backend(false, false, "backend-selection-test");
        println!("Backend creation result: {:?}", result.is_ok());
    }

    #[test]
    fn test_backend_type_name() {
        assert_eq!(backend_type_name(CgroupBackendType::V1), "cgroup_v1");
        assert_eq!(backend_type_name(CgroupBackendType::V2), "cgroup_v2");
    }

    #[test]
    fn test_backend_selection_force_v1() {
        // Test forcing v1 in permissive mode
        let result = create_cgroup_backend(true, false, "force-v1-test");
        // Should either succeed with v1 or fail gracefully
        println!("Force v1 result: {:?}", result.is_ok());
    }

    #[test]
    fn test_backend_selection_default() {
        // Test default selection (v2 preferred, v1 fallback)
        let result = create_cgroup_backend(false, false, "default-selection-test");
        // Should either succeed or fail gracefully in permissive mode
        println!("Default selection result: {:?}", result.is_ok());
    }
}
