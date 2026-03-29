//! Integration tests for kernel namespace module

#[cfg(target_os = "linux")]
mod namespace_tests {
    use rustbox::kernel::namespace::{harden_mount_propagation, NamespaceIsolation};

    fn running_as_root() -> bool {
        // SAFETY: geteuid has no side effects and needs no arguments.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn test_namespace_isolation_pid_mount_network() {
        let ns = NamespaceIsolation::new(true, true, true, false, false, false);

        let enabled = ns.get_enabled_namespaces();
        assert!(enabled.contains(&"PID"));
        assert!(enabled.contains(&"Mount"));
        assert!(enabled.contains(&"Network"));
        assert!(!enabled.contains(&"User"));
    }

    #[test]
    fn test_namespace_isolation_all_except_user() {
        let ns = NamespaceIsolation::new(true, true, true, false, true, true);

        let enabled = ns.get_enabled_namespaces();
        assert!(enabled.contains(&"PID"));
        assert!(enabled.contains(&"Mount"));
        assert!(enabled.contains(&"Network"));
        assert!(enabled.contains(&"IPC"));
        assert!(enabled.contains(&"UTS"));
        assert!(!enabled.contains(&"User"));
    }

    #[test]
    fn test_namespace_isolation_default() {
        let ns = NamespaceIsolation::new(true, true, true, false, true, true);

        let enabled = ns.get_enabled_namespaces();
        assert!(enabled.contains(&"PID"));
        assert!(enabled.contains(&"Mount"));
        assert!(enabled.contains(&"Network"));
        assert!(!enabled.contains(&"User"));
    }

    #[test]
    fn test_namespace_isolation_is_enabled() {
        let ns_enabled = NamespaceIsolation::new(true, false, false, false, false, false);
        assert!(ns_enabled.is_isolation_enabled());

        let ns_disabled = NamespaceIsolation::new(false, false, false, false, false, false);
        assert!(!ns_disabled.is_isolation_enabled());
    }

    #[test]
    fn test_namespace_support_detection() {
        // This should always be true on Linux
        assert!(NamespaceIsolation::is_supported());
    }

    #[test]
    fn test_namespace_isolation_new() {
        let ns = NamespaceIsolation::new(true, true, false, false, true, false);

        let enabled = ns.get_enabled_namespaces();
        assert_eq!(enabled.len(), 3);
        assert!(enabled.contains(&"PID"));
        assert!(enabled.contains(&"Mount"));
        assert!(enabled.contains(&"IPC"));
    }

    #[test]
    fn test_get_enabled_namespaces_empty() {
        let ns = NamespaceIsolation::new(false, false, false, false, false, false);

        let enabled = ns.get_enabled_namespaces();
        assert_eq!(enabled.len(), 0);
    }

    #[test]
    fn test_get_enabled_namespaces_all() {
        let ns = NamespaceIsolation::new(true, true, true, true, true, true);

        let enabled = ns.get_enabled_namespaces();
        assert_eq!(enabled.len(), 6);
        assert!(enabled.contains(&"PID"));
        assert!(enabled.contains(&"Mount"));
        assert!(enabled.contains(&"Network"));
        assert!(enabled.contains(&"User"));
        assert!(enabled.contains(&"IPC"));
        assert!(enabled.contains(&"UTS"));
    }

    #[test]
    fn test_apply_isolation_requires_privileges() {
        if !running_as_root() {
            eprintln!("Skipping root-only namespace isolation test");
            return;
        }

        let ns = NamespaceIsolation::new(true, true, false, false, false, false);

        let result = ns.apply_isolation();
        if let Err(e) = result {
            assert!(e.to_string().contains("Failed to unshare namespaces"));
        }
    }

    #[test]
    fn test_harden_mount_propagation_requires_privileges() {
        if !running_as_root() {
            eprintln!("Skipping root-only mount propagation test");
            return;
        }

        let result = harden_mount_propagation();
        if let Err(e) = result {
            assert!(e
                .to_string()
                .contains("CRITICAL: Failed to harden mount propagation"));
        }
    }

    #[test]
    fn test_all_namespaces_enabled() {
        let ns = NamespaceIsolation::new(true, true, true, false, true, true);

        assert_eq!(ns.get_enabled_namespaces().len(), 5);
    }

    #[test]
    fn test_no_namespaces_enabled() {
        let ns = NamespaceIsolation::new(false, false, false, false, false, false);

        assert_eq!(ns.get_enabled_namespaces().len(), 0);
        assert!(!ns.is_isolation_enabled());
    }
}
