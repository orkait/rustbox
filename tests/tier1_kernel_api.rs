mod common;

use rustbox::config::constants;
use rustbox::kernel::capabilities::{get_bounding_set, get_capability_status};
use rustbox::kernel::cgroup::sanitize_instance_id;
use rustbox::kernel::credentials::validate_ids;
use rustbox::kernel::namespace::NamespaceIsolation;

#[test]
fn bounding_set_is_readable() {
    let caps = get_bounding_set().expect("get_bounding_set must not fail");
    assert!(
        !caps.is_empty(),
        "unprivileged process should have at least some bounding capabilities"
    );
}

#[test]
fn capability_status_contains_cap_lines() {
    let status = get_capability_status().expect("get_capability_status must not fail");
    assert!(
        status.contains("Cap"),
        "capability status must contain at least one Cap line"
    );
    for prefix in &["CapInh:", "CapPrm:", "CapEff:", "CapBnd:"] {
        assert!(
            status.contains(prefix),
            "capability status must contain '{}' line",
            prefix
        );
    }
}

#[test]
fn validate_ids_rejects_root_strict() {
    assert!(validate_ids(0, 1000, true).is_err());
    assert!(validate_ids(1000, 0, true).is_err());
    assert!(validate_ids(0, 0, true).is_err());
}

#[test]
fn validate_ids_allows_root_permissive() {
    assert!(validate_ids(0, 0, false).is_ok());
    assert!(validate_ids(0, 1000, false).is_ok());
    assert!(validate_ids(1000, 0, false).is_ok());
}

#[test]
fn validate_ids_accepts_non_root() {
    assert!(validate_ids(constants::NOBODY_UID, constants::NOBODY_GID, true).is_ok());
    assert!(validate_ids(60000, 60000, true).is_ok());
    assert!(validate_ids(1000, 1000, true).is_ok());
}

#[test]
fn sanitize_instance_id_blocks_path_traversal() {
    assert_eq!(sanitize_instance_id(".."), "default");
    assert_eq!(sanitize_instance_id("../../../etc/passwd"), "default");
    assert_eq!(sanitize_instance_id("foo..bar"), "default");
    assert_eq!(sanitize_instance_id("."), "default");
    assert_eq!(sanitize_instance_id(""), "default");
}

#[test]
fn sanitize_instance_id_allows_valid_ids() {
    assert_eq!(sanitize_instance_id("box-42"), "box-42");
    assert_eq!(sanitize_instance_id("rustbox_1"), "rustbox_1");
    assert_eq!(sanitize_instance_id("test.instance"), "test.instance");
    assert_eq!(sanitize_instance_id("abc123"), "abc123");
}

#[test]
fn sanitize_instance_id_replaces_special_chars() {
    let result = sanitize_instance_id("test/foo:bar");
    assert!(!result.contains('/'));
    assert!(!result.contains(':'));
    assert!(!result.is_empty());
}

#[test]
fn namespace_isolation_builder_creates_correct_config() {
    let ns = NamespaceIsolation::builder()
        .with_pid()
        .with_mount()
        .with_network()
        .build();

    let enabled = ns.get_enabled_namespaces();
    assert!(enabled.contains(&"PID"));
    assert!(enabled.contains(&"Mount"));
    assert!(enabled.contains(&"Network"));
    assert!(!enabled.contains(&"User"));
}

#[test]
fn namespace_isolation_default_enables_standard_set() {
    let ns = NamespaceIsolation::new_default();
    let enabled = ns.get_enabled_namespaces();
    assert!(enabled.contains(&"PID"));
    assert!(enabled.contains(&"Mount"));
    assert!(enabled.contains(&"Network"));
    assert!(!enabled.contains(&"User"));
    assert!(enabled.contains(&"IPC"));
    assert!(enabled.contains(&"UTS"));
    assert!(ns.is_isolation_enabled());
}

#[test]
fn pipeline_rejects_out_of_order_stages() {
    use rustbox::kernel::contract::{EnforcementMode, KernelDomain, KernelRequirement};
    use rustbox::kernel::pipeline::{KernelPipeline, KernelStage};

    struct DummyStage {
        name: &'static str,
        domain: KernelDomain,
    }

    impl KernelStage for DummyStage {
        fn name(&self) -> &'static str {
            self.name
        }
        fn domain(&self) -> KernelDomain {
            self.domain
        }
        fn requirements(&self) -> &'static [KernelRequirement] {
            &[]
        }
        fn apply(&self, _: EnforcementMode) -> rustbox::config::types::Result<()> {
            Ok(())
        }
        fn verify(&self, _: EnforcementMode) -> rustbox::config::types::Result<()> {
            Ok(())
        }
    }

    let signal = DummyStage {
        name: "signal",
        domain: KernelDomain::Signal,
    };
    let mount = DummyStage {
        name: "mount",
        domain: KernelDomain::Mount,
    };

    let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
    pipeline.push_stage(&signal).push_stage(&mount);
    assert!(
        pipeline.validate_order().is_err(),
        "signal before mount must violate ordering"
    );
}

#[test]
fn pipeline_runs_complete_stage_set() {
    use rustbox::kernel::contract::{EnforcementMode, KernelDomain, KernelRequirement};
    use rustbox::kernel::pipeline::{KernelPipeline, KernelStage};

    struct DummyStage {
        name: &'static str,
        domain: KernelDomain,
    }

    impl KernelStage for DummyStage {
        fn name(&self) -> &'static str {
            self.name
        }
        fn domain(&self) -> KernelDomain {
            self.domain
        }
        fn requirements(&self) -> &'static [KernelRequirement] {
            &[]
        }
        fn apply(&self, _: EnforcementMode) -> rustbox::config::types::Result<()> {
            Ok(())
        }
        fn verify(&self, _: EnforcementMode) -> rustbox::config::types::Result<()> {
            Ok(())
        }
    }

    let stages = [
        DummyStage {
            name: "namespace",
            domain: KernelDomain::Namespace,
        },
        DummyStage {
            name: "mount",
            domain: KernelDomain::Mount,
        },
        DummyStage {
            name: "cgroup",
            domain: KernelDomain::Cgroup,
        },
        DummyStage {
            name: "credentials",
            domain: KernelDomain::Credentials,
        },
        DummyStage {
            name: "capabilities",
            domain: KernelDomain::Capabilities,
        },
        DummyStage {
            name: "signal",
            domain: KernelDomain::Signal,
        },
        DummyStage {
            name: "cleanup",
            domain: KernelDomain::Cleanup,
        },
        DummyStage {
            name: "evidence",
            domain: KernelDomain::Evidence,
        },
        DummyStage {
            name: "seccomp",
            domain: KernelDomain::Seccomp,
        },
    ];

    let mut pipeline = KernelPipeline::new(EnforcementMode::Strict);
    for stage in &stages {
        pipeline.push_stage(stage);
    }

    let report = pipeline
        .run()
        .expect("complete pipeline must run successfully");
    assert_eq!(report.applied_stages.len(), 9);
    assert_eq!(report.verified_stages.len(), 9);
    assert_eq!(report.applied_stages[0], "namespace");
    assert_eq!(report.applied_stages[8], "seccomp");
    assert_eq!(report.applied_stages, report.verified_stages);
}
