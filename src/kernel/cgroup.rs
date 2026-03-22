use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::path::PathBuf;

use super::cgroup_v1::CgroupV1;
use super::cgroup_v2::CgroupV2;

pub(crate) fn sanitize_instance_id(instance_id: &str) -> String {
    let sanitized: String = instance_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let trimmed = sanitized.trim_matches('_').to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." || trimmed.contains("..") {
        "default".to_string()
    } else {
        trimmed
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupBackendType {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSelector {
    AutoPreferV2,
    ForceV1,
}

impl BackendSelector {
    pub const fn auto() -> Self {
        Self::AutoPreferV2
    }

    pub const fn force_v1() -> Self {
        Self::ForceV1
    }

    pub const fn from_force_v1(force_v1: bool) -> Self {
        if force_v1 {
            Self::ForceV1
        } else {
            Self::AutoPreferV2
        }
    }
}

pub struct SelectedBackend {
    pub backend_type: CgroupBackendType,
    pub backend: Box<dyn CgroupBackend>,
}

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

pub fn backend_type_name(backend_type: CgroupBackendType) -> &'static str {
    match backend_type {
        CgroupBackendType::V1 => "cgroup_v1",
        CgroupBackendType::V2 => "cgroup_v2",
    }
}

pub fn select_cgroup_backend(
    selector: BackendSelector,
    strict_mode: bool,
    instance_id: &str,
) -> Result<SelectedBackend> {
    let detected = detect_cgroup_backend();
    log::info!(
        "cgroup backend selector: selector={:?}, strict_mode={}, detected={:?}",
        selector,
        strict_mode,
        detected
    );

    match selector {
        BackendSelector::AutoPreferV2 => match detected {
            Some(CgroupBackendType::V2) => Ok(SelectedBackend {
                backend_type: CgroupBackendType::V2,
                backend: Box::new(CgroupV2::new(instance_id, strict_mode)?),
            }),
            Some(CgroupBackendType::V1) => Ok(SelectedBackend {
                backend_type: CgroupBackendType::V1,
                backend: Box::new(CgroupV1::new(instance_id, strict_mode)?),
            }),
            None => Err(IsolateError::Cgroup(
                "No cgroup backend available on this host".to_string(),
            )),
        },
        BackendSelector::ForceV1 => match detected {
            Some(CgroupBackendType::V1) => Ok(SelectedBackend {
                backend_type: CgroupBackendType::V1,
                backend: Box::new(CgroupV1::new(instance_id, strict_mode)?),
            }),
            Some(CgroupBackendType::V2) => {
                if strict_mode {
                    Err(IsolateError::Cgroup(
                        "cgroup v1 forced, but host only exposes v2 in strict mode".to_string(),
                    ))
                } else {
                    log::warn!("cgroup v1 forced but unavailable; falling back to cgroup v2");
                    Ok(SelectedBackend {
                        backend_type: CgroupBackendType::V2,
                        backend: Box::new(CgroupV2::new(instance_id, false)?),
                    })
                }
            }
            None => Err(IsolateError::Cgroup(
                "cgroup v1 forced, but no cgroup backend is available".to_string(),
            )),
        },
    }
}

pub fn create_cgroup_backend(
    force_v1: bool,
    strict_mode: bool,
    instance_id: &str,
) -> Result<Box<dyn CgroupBackend>> {
    let selector = BackendSelector::from_force_v1(force_v1);
    let selected = select_cgroup_backend(selector, strict_mode, instance_id)?;
    Ok(selected.backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_type_name_is_stable() {
        assert_eq!(backend_type_name(CgroupBackendType::V1), "cgroup_v1");
        assert_eq!(backend_type_name(CgroupBackendType::V2), "cgroup_v2");
    }

    #[test]
    fn selector_conversion_is_deterministic() {
        assert_eq!(
            BackendSelector::from_force_v1(false),
            BackendSelector::AutoPreferV2
        );
        assert_eq!(BackendSelector::from_force_v1(true), BackendSelector::ForceV1);
    }

    #[test]
    fn sanitize_instance_id_blocks_path_traversal() {
        assert_eq!(sanitize_instance_id(".."), "default");
        assert_eq!(sanitize_instance_id("../../../etc/passwd"), "default");
        assert_eq!(sanitize_instance_id("foo..bar"), "default");
        assert_eq!(sanitize_instance_id("a/.."), "default");
        assert_eq!(sanitize_instance_id("."), "default");
    }

    #[test]
    fn sanitize_instance_id_allows_valid_ids() {
        assert_eq!(sanitize_instance_id("box-42"), "box-42");
        assert_eq!(sanitize_instance_id("rustbox_1"), "rustbox_1");
        assert_eq!(sanitize_instance_id("test.instance"), "test.instance");
    }
}
