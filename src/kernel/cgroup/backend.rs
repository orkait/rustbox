//! Cgroup backend abstraction for v1/v2 dual support.

use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::path::PathBuf;

pub trait CgroupBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn create(&self, instance_id: &str) -> Result<()>;
    fn remove(&self, instance_id: &str) -> Result<()>;
    fn attach_process(&self, instance_id: &str, pid: u32) -> Result<()>;
    fn set_memory_limit(&self, instance_id: &str, limit_bytes: u64) -> Result<()>;
    fn set_process_limit(&self, instance_id: &str, limit: u32) -> Result<()>;
    fn set_cpu_limit(&self, instance_id: &str, limit_usec: u64) -> Result<()>;
    fn get_memory_usage(&self) -> Result<u64>;
    fn get_memory_peak(&self) -> Result<u64>;
    fn get_cpu_usage(&self) -> Result<u64>;
    fn get_process_count(&self) -> Result<u32>;
    fn check_oom(&self) -> Result<bool>;
    fn get_oom_kill_count(&self) -> Result<u64>;
    fn collect_evidence(&self, instance_id: &str) -> Result<CgroupEvidence>;
    fn get_cgroup_path(&self, instance_id: &str) -> PathBuf;
    fn is_empty(&self) -> Result<bool>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupBackendType {
    V1,
    V2,
}

/// Detect available cgroup backend: v2 preferred, v1 fallback.
pub fn detect_cgroup_backend() -> Option<CgroupBackendType> {
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Some(CgroupBackendType::V2);
    }
    if std::path::Path::new("/sys/fs/cgroup/memory").exists()
        && std::path::Path::new("/sys/fs/cgroup/cpu").exists()
    {
        return Some(CgroupBackendType::V1);
    }
    None
}

/// Create cgroup backend: v2 default, --cgroup-v1 forces v1, automatic fallback.
pub fn create_cgroup_backend(
    force_v1: bool,
    strict_mode: bool,
    instance_id: &str,
) -> Result<Box<dyn CgroupBackend>> {
    let detected = detect_cgroup_backend();

    log::info!(
        "Cgroup backend selection: force_v1={}, strict_mode={}, detected={:?}",
        force_v1, strict_mode, detected
    );

    if force_v1 {
        log::info!("Cgroup v1 explicitly requested via --cgroup-v1 flag");
        match detected {
            Some(CgroupBackendType::V1) => {
                log::info!("Using cgroup v1 backend (explicit override)");
                Ok(Box::new(crate::kernel::cgroup::v1::Cgroup::new(instance_id, strict_mode)?))
            }
            Some(CgroupBackendType::V2) => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "Cgroup v1 forced but only v2 available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("Cgroup v1 forced but only v2 available, using v2 anyway");
                    Ok(Box::new(crate::kernel::cgroup::v2::CgroupV2::new(instance_id, false)?))
                }
            }
            None => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "Cgroup v1 forced but not available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("Cgroup v1 forced but not available, continuing without cgroups");
                    Err(IsolateError::Cgroup("Cgroup v1 forced but not available".to_string()))
                }
            }
        }
    } else {
        match detected {
            Some(CgroupBackendType::V2) => {
                log::info!("Using cgroup v2 backend (default)");
                Ok(Box::new(crate::kernel::cgroup::v2::CgroupV2::new(instance_id, strict_mode)?))
            }
            Some(CgroupBackendType::V1) => {
                log::info!("Using cgroup v1 backend (fallback, v2 not available)");
                Ok(Box::new(crate::kernel::cgroup::v1::Cgroup::new(instance_id, strict_mode)?))
            }
            None => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "No cgroup backend available in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("No cgroup backend available, continuing without resource limits");
                    Err(IsolateError::Cgroup("No cgroup backend available".to_string()))
                }
            }
        }
    }
}

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
        let _backend = detect_cgroup_backend();
    }

    #[test]
    fn test_backend_selection() {
        let _result = create_cgroup_backend(false, false, "backend-selection-test");
    }

    #[test]
    fn test_backend_type_name() {
        assert_eq!(backend_type_name(CgroupBackendType::V1), "cgroup_v1");
        assert_eq!(backend_type_name(CgroupBackendType::V2), "cgroup_v2");
    }

    #[test]
    fn test_backend_selection_force_v1() {
        let _result = create_cgroup_backend(true, false, "force-v1-test");
    }

    #[test]
    fn test_backend_selection_default() {
        let _result = create_cgroup_backend(false, false, "default-selection-test");
    }
}
