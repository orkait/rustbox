use std::path::Path;

pub fn is_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

pub fn docker_cgroup_hint() -> &'static str {
    "Cgroup unavailable inside container. Run with:\n  \
     --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \\\n  \
     --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \\\n  \
     --security-opt seccomp=unconfined --cgroupns=host"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_container_returns_bool() {
        let _ = is_container();
    }

    #[test]
    fn docker_hint_is_nonempty() {
        assert!(docker_cgroup_hint().contains("--cap-add SYS_ADMIN"));
    }
}
