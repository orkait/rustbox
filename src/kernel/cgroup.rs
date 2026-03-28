use crate::config::types::{CgroupEvidence, IsolateError, Result};
use std::path::PathBuf;

use super::cgroup_v2::CgroupV2;

pub(crate) fn sanitize_instance_id(instance_id: &str) -> String {
    let sanitized: String = instance_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
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

pub(crate) fn read_cgroup_u64(path: &std::path::Path, field_name: &str) -> Result<u64> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        IsolateError::Cgroup(format!(
            "failed to read {} ({}): {}",
            field_name,
            path.display(),
            e
        ))
    })?;
    raw.trim().parse::<u64>().map_err(|e| {
        IsolateError::Cgroup(format!(
            "failed to parse {} ({}): {}",
            field_name,
            path.display(),
            e
        ))
    })
}

pub(crate) fn read_cgroup_optional_limit(
    path: &std::path::Path,
    field_name: &str,
) -> Result<Option<u64>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(IsolateError::Cgroup(format!(
                "failed to read {} ({}): {}",
                field_name,
                path.display(),
                err
            )));
        }
    };
    let value = raw.trim();
    if value == "max" {
        return Ok(None);
    }
    value.parse::<u64>().map(Some).map_err(|err| {
        IsolateError::Cgroup(format!(
            "failed to parse {} ({}): {}",
            field_name,
            path.display(),
            err
        ))
    })
}

pub(crate) fn write_cgroup_value(
    path: &std::path::Path,
    value: &impl ToString,
    strict_mode: bool,
    name: &str,
) -> Result<()> {
    if let Err(err) = std::fs::write(path, value.to_string()) {
        if strict_mode {
            return Err(IsolateError::Cgroup(format!(
                "failed to write {} ({}): {}",
                name,
                path.display(),
                err
            )));
        }
        log::warn!(
            "failed to write {} ({}), continuing in permissive mode: {}",
            name,
            path.display(),
            err
        );
    }
    Ok(())
}

pub(crate) fn collect_cgroup_metric<T>(
    strict_mode: bool,
    field_name: &str,
    result: Result<T>,
    fallback: T,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) if strict_mode => Err(IsolateError::Cgroup(format!(
            "failed collecting {} in strict mode: {}",
            field_name, err
        ))),
        Err(err) => {
            log::warn!(
                "failed collecting {} in permissive mode: {}",
                field_name,
                err
            );
            Ok(fallback)
        }
    }
}

pub(crate) fn collect_cgroup_optional_metric<T>(
    strict_mode: bool,
    field_name: &str,
    result: Result<T>,
) -> Result<Option<T>> {
    collect_cgroup_metric(strict_mode, field_name, result.map(Some), None)
}

#[must_use]
pub fn is_cgroup_v2_available() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

pub fn select_cgroup_backend(
    strict_mode: bool,
    instance_id: &str,
) -> Result<Box<dyn CgroupBackend>> {
    if is_cgroup_v2_available() {
        let backend = CgroupV2::new(instance_id, strict_mode)?;
        return Ok(Box::new(backend));
    }

    let mut msg = "Cgroup v2 not available on this host.\n\
                   Rustbox requires cgroup v2 for resource enforcement.\n\
                   Enable with: systemd.unified_cgroup_hierarchy=1 on kernel command line"
        .to_string();
    if crate::utils::container::is_container() {
        msg.push_str(".\n");
        msg.push_str(crate::utils::container::docker_cgroup_hint());
    }
    Err(IsolateError::Cgroup(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn v2_detection_returns_bool() {
        let _ = is_cgroup_v2_available();
    }
}
