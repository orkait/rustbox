//! Integration tests for kernel mount module

#[cfg(target_os = "linux")]
mod mount_tests {
    use rustbox::config::types::{DirectoryBinding, DirectoryPermissions};
    use rustbox::kernel::mount::FilesystemSecurity;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_filesystem_security_creation() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            false,
            None,
            None,
        );
        assert!(!fs_sec.is_isolated());
    }

    #[test]
    fn test_filesystem_security_with_chroot() {
        let chroot_path = PathBuf::from("/tmp/rustbox-test-chroot");
        let fs_sec = FilesystemSecurity::new(
            Some(chroot_path),
            PathBuf::from("/tmp/rustbox-test-workdir"),
            false,
            None,
            None,
        );
        assert!(fs_sec.is_isolated());
    }

    #[test]
    fn test_strict_mode_rejects_read_write_bindings() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
        );

        let binding = DirectoryBinding {
            source: PathBuf::from("/tmp/host-data"),
            target: PathBuf::from("/data"),
            permissions: DirectoryPermissions::ReadWrite,
            maybe: true,
            is_tmp: false,
        };

        let result = fs_sec.setup_directory_bindings(&[binding]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Read-write directory bindings are disallowed"));
    }

    #[test]
    fn test_strict_mode_accepts_read_only_bindings() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
        );

        // Create a temporary source directory
        let source_dir = PathBuf::from("/tmp/rustbox-test-source");
        let _ = fs::create_dir_all(&source_dir);

        let binding = DirectoryBinding {
            source: source_dir.clone(),
            target: PathBuf::from("/data"),
            permissions: DirectoryPermissions::ReadOnly,
            maybe: true,
            is_tmp: false,
        };

        // This should not error in strict mode
        let result = fs_sec.setup_directory_bindings(&[binding]);
        // May fail due to permissions, but should not fail due to strict mode check
        if let Err(e) = result {
            assert!(!e
                .to_string()
                .contains("Read-write directory bindings are disallowed"));
        }

        // Cleanup
        let _ = fs::remove_dir_all(&source_dir);
    }

    #[test]
    fn test_validate_path_rejects_dangerous_paths() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
        );

        let dangerous_paths = vec![
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/etc/shadow"),
            PathBuf::from("/root"),
        ];

        for path in dangerous_paths {
            if path.exists() {
                let result = fs_sec.validate_path(&path);
                assert!(result.is_err(), "Should reject dangerous path: {:?}", path);
            }
        }
    }

    #[test]
    fn test_effective_workdir_without_chroot() {
        let workdir = PathBuf::from("/tmp/rustbox-test-workdir");
        let fs_sec = FilesystemSecurity::new(None, workdir.clone(), false, None, None);

        assert_eq!(fs_sec.get_effective_workdir(), workdir);
    }

    #[test]
    fn test_effective_workdir_with_chroot() {
        let workdir = PathBuf::from("/tmp/rustbox-test-workdir");
        let chroot_path = PathBuf::from("/tmp/rustbox-test-chroot");
        let fs_sec = FilesystemSecurity::new(Some(chroot_path), workdir.clone(), false, None, None);

        let effective = fs_sec.get_effective_workdir();
        assert!(effective.starts_with("/"));
        assert!(effective.to_string_lossy().contains("rustbox-test-workdir"));
    }

    #[test]
    fn test_tmpfs_size_limits() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            Some(128 * 1024 * 1024), // 128 MB
            Some(10_000),
        );

        // Just verify it doesn't panic
        assert!(!fs_sec.is_isolated());
    }

    #[test]
    fn test_maybe_binding_skips_nonexistent() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            false,
            None,
            None,
        );

        let binding = DirectoryBinding {
            source: PathBuf::from("/tmp/nonexistent-rustbox-test-dir-12345"),
            target: PathBuf::from("/data"),
            permissions: DirectoryPermissions::ReadOnly,
            maybe: true,
            is_tmp: false,
        };

        // Should succeed (skip) for non-existent with maybe=true
        let result = fs_sec.setup_directory_bindings(&[binding]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cleanup_is_safe() {
        let fs_sec = FilesystemSecurity::new(
            None,
            PathBuf::from("/tmp/rustbox-test-workdir"),
            false,
            None,
            None,
        );

        // Cleanup should not fail even if nothing was set up
        let result = fs_sec.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn test_path_traversal_rejected() {
        let fs_sec = FilesystemSecurity::new(
            Some(PathBuf::from("/tmp/rustbox-test-chroot")),
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
        );

        // Test path traversal with ".."
        let binding = DirectoryBinding {
            source: PathBuf::from("/tmp/host-data"),
            target: PathBuf::from("../../../etc"),
            permissions: DirectoryPermissions::ReadOnly,
            maybe: false,
            is_tmp: false,
        };

        let result = fs_sec.setup_directory_bindings(&[binding]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Path traversal detected"));
    }

    #[test]
    fn test_path_traversal_with_absolute_path() {
        let fs_sec = FilesystemSecurity::new(
            Some(PathBuf::from("/tmp/rustbox-test-chroot")),
            PathBuf::from("/tmp/rustbox-test-workdir"),
            true,
            None,
            None,
        );

        // Test path traversal with absolute path containing ".."
        let binding = DirectoryBinding {
            source: PathBuf::from("/tmp/host-data"),
            target: PathBuf::from("/data/../../../etc"),
            permissions: DirectoryPermissions::ReadOnly,
            maybe: false,
            is_tmp: false,
        };

        let result = fs_sec.setup_directory_bindings(&[binding]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Path traversal detected"));
    }

    #[test]
    fn test_workdir_created_inside_chroot() {
        let chroot_path = PathBuf::from("/tmp/rustbox-test-chroot-workdir");
        let workdir = PathBuf::from("/workspace");

        // Create chroot directory
        let _ = fs::create_dir_all(&chroot_path);

        let mut fs_sec = FilesystemSecurity::new(
            Some(chroot_path.clone()),
            workdir.clone(),
            false,
            None,
            None,
        );

        // Setup should create workdir inside chroot, not on host root
        let result = fs_sec.setup_isolation();

        // Verify workdir was created inside chroot
        let expected_workdir = chroot_path.join("workspace");
        if result.is_ok() {
            // In permissive mode, this should succeed
            assert!(expected_workdir.exists() || !chroot_path.exists());
        }

        // Cleanup
        let _ = fs::remove_dir_all(&chroot_path);
    }
}
