#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    Strict,
    Permissive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelDomain {
    Namespace,
    Mount,
    Credentials,
    Capabilities,
    Cgroup,
    Signal,
    Cleanup,
    Evidence,
    Seccomp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,
    Should,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelRequirement {
    pub id: &'static str,
    pub domain: KernelDomain,
    pub level: RequirementLevel,
    pub statement: &'static str,
}

pub const REQUIRED_STAGE_ORDER: &[KernelDomain] = &[
    KernelDomain::Namespace,
    KernelDomain::Mount,
    KernelDomain::Cgroup,
    KernelDomain::Credentials,
    KernelDomain::Capabilities,
    KernelDomain::Signal,
    KernelDomain::Cleanup,
    KernelDomain::Evidence,
    KernelDomain::Seccomp,
];

pub const KERNEL_REQUIREMENTS: &[KernelRequirement] = &[
    KernelRequirement {
        id: "KV2-NS-001",
        domain: KernelDomain::Namespace,
        level: RequirementLevel::Must,
        statement: "Mount propagation must be hardened (MS_PRIVATE|MS_REC on /) before any mount operations.",
    },
    KernelRequirement {
        id: "KV2-NS-002",
        domain: KernelDomain::Namespace,
        level: RequirementLevel::Must,
        statement: "Namespace policy (pid/mount/net/user/ipc/uts) must be explicit and auditable per run.",
    },
    KernelRequirement {
        id: "KV2-MT-001",
        domain: KernelDomain::Mount,
        level: RequirementLevel::Must,
        statement: "Strict mode must forbid read-write host bind mounts.",
    },
    KernelRequirement {
        id: "KV2-MT-002",
        domain: KernelDomain::Mount,
        level: RequirementLevel::Must,
        statement: "Target mount paths must reject parent traversal and resolve under allowed root.",
    },
    KernelRequirement {
        id: "KV2-CR-001",
        domain: KernelDomain::Credentials,
        level: RequirementLevel::Must,
        statement: "Privilege transition order must be: clear groups, setresgid, then setresuid, then verify.",
    },
    KernelRequirement {
        id: "KV2-CR-002",
        domain: KernelDomain::Credentials,
        level: RequirementLevel::Must,
        statement: "Strict mode must fail on any UID/GID transition verification mismatch.",
    },
    KernelRequirement {
        id: "KV2-CP-001",
        domain: KernelDomain::Capabilities,
        level: RequirementLevel::Must,
        statement: "Kernel must set PR_SET_NO_NEW_PRIVS before executing untrusted payloads.",
    },
    KernelRequirement {
        id: "KV2-CP-002",
        domain: KernelDomain::Capabilities,
        level: RequirementLevel::Must,
        statement: "Strict capability verification must include inheritable, permitted, effective, bounding, and ambient sets.",
    },
    KernelRequirement {
        id: "KV2-CG-001",
        domain: KernelDomain::Cgroup,
        level: RequirementLevel::Must,
        statement: "Cgroup instance identity contract must be consistent across v1/v2 and all callers.",
    },
    KernelRequirement {
        id: "KV2-CG-002",
        domain: KernelDomain::Cgroup,
        level: RequirementLevel::Must,
        statement: "Strict mode must fail closed when controller delegation/setup is missing.",
    },
    KernelRequirement {
        id: "KV2-CG-003",
        domain: KernelDomain::Cgroup,
        level: RequirementLevel::Must,
        statement: "No strictness downgrade is allowed in fallback backend selection.",
    },
    KernelRequirement {
        id: "KV2-SG-001",
        domain: KernelDomain::Signal,
        level: RequirementLevel::Must,
        statement: "Signal handlers must remain async-signal-safe (atomics only; no allocation/locking/I/O).",
    },
    KernelRequirement {
        id: "KV2-CL-001",
        domain: KernelDomain::Cleanup,
        level: RequirementLevel::Must,
        statement: "Cleanup must be deterministic, idempotent, and bounded with retry/backoff limits.",
    },
    KernelRequirement {
        id: "KV2-EV-001",
        domain: KernelDomain::Evidence,
        level: RequirementLevel::Must,
        statement: "Each enforcement domain must emit kernel-truth evidence (/proc, cgroupfs, wait status).",
    },
    KernelRequirement {
        id: "KV2-EV-002",
        domain: KernelDomain::Evidence,
        level: RequirementLevel::Should,
        statement: "Evidence collection should degrade gracefully only in permissive mode with explicit audit warnings.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn requirement_ids_are_unique() {
        let mut ids = HashSet::new();
        for req in KERNEL_REQUIREMENTS {
            assert!(ids.insert(req.id), "duplicate requirement id: {}", req.id);
        }
    }

    #[test]
    fn required_stage_order_has_unique_domains() {
        let mut seen = HashSet::new();
        for domain in REQUIRED_STAGE_ORDER {
            assert!(
                seen.insert(*domain),
                "duplicate stage domain in order: {:?}",
                domain
            );
        }
    }
}
