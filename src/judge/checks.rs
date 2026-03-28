use std::path::Path;

pub fn perform_security_checks() {
    if crate::kernel::cgroup::is_cgroup_v2_available() {
        eprintln!("✅ cgroup v2 available - resource limits enabled");
    } else {
        eprintln!("⚠️  Warning: cgroups not available - resource limits will not be enforced");
        eprintln!("   Ensure /proc/cgroups and /sys/fs/cgroup are properly mounted");
        eprintln!("   Some contest systems may not function correctly without cgroups");
    }

    if crate::kernel::namespace::NamespaceIsolation::is_supported() {
        eprintln!("✅ namespace isolation available - full process isolation enabled");
    } else {
        eprintln!("⚠️  Warning: namespace isolation not supported");
        eprintln!("   Limited process isolation capabilities available");
    }

    if Path::new("/proc/self/ns").exists() {
        eprintln!("✅ namespace filesystem available - isolation monitoring enabled");
    }

    validate_system_directories();
}

fn validate_system_directories() {
    if !Path::new("/tmp").exists() || !Path::new("/tmp").is_dir() {
        eprintln!("⚠️  Warning: /tmp directory not accessible");
        eprintln!("   Sandbox operations may fail without writable temporary space");
    }

    if !Path::new("/proc/self").exists() {
        eprintln!("⚠️  Warning: /proc filesystem not mounted");
        eprintln!("   Process monitoring and resource tracking may be limited");
    }

    if !Path::new("/sys").exists() {
        eprintln!("⚠️  Warning: /sys filesystem not mounted");
        eprintln!("   Cgroups and hardware information may be unavailable");
    }

    let sensitive_dirs = ["/etc", "/root", "/boot"];
    for dir in &sensitive_dirs {
        if !Path::new(dir).exists() {
            eprintln!("⚠️  Warning: {} directory not found", dir);
        }
    }
}
