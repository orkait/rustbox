use crate::config::types::{IsolateError, Result};
use crate::exec::preexec::{FreshChild, Sandbox};
use crate::sandbox::types::SandboxLaunchRequest;
use crate::utils::fork_safe_log::{fs_debug_parts, fs_warn_parts, itoa_buf, itoa_i32, raw_write};

use crate::kernel::contract::{EnforcementMode, KernelDomain, KernelRequirement};
use crate::kernel::pipeline::{KernelPipeline, KernelRunReport, KernelStage};

#[derive(Clone, Copy)]
struct StaticStage {
    name: &'static str,
    domain: KernelDomain,
}

impl KernelStage for StaticStage {
    fn name(&self) -> &'static str {
        self.name
    }

    fn domain(&self) -> KernelDomain {
        self.domain
    }

    fn requirements(&self) -> &'static [KernelRequirement] {
        &[]
    }

    fn apply(&self, _mode: EnforcementMode) -> Result<()> {
        Ok(())
    }

    fn verify(&self, _mode: EnforcementMode) -> Result<()> {
        Ok(())
    }
}

const STAGE_NAMESPACE_SETUP: &str = "namespace_setup";
const STAGE_MOUNT_HARDENING: &str = "mount_propagation_hardening";
const STAGE_CGROUP_ATTACH: &str = "cgroup_attach";
const STAGE_MOUNT_ROOT_TRANSITION: &str = "mount_root_transition";
const STAGE_RUNTIME_HYGIENE: &str = "runtime_hygiene";
const STAGE_CREDENTIALS: &str = "credential_transition";
const STAGE_CAPABILITIES: &str = "capability_lockdown";
const STAGE_SIGNAL_HANDOFF: &str = "signal_handoff_verification";
const STAGE_SESSION_LEADERSHIP: &str = "session_leadership_verification";
const STAGE_EVIDENCE: &str = "post_lock_evidence";
const STAGE_SECCOMP: &str = "seccomp_filter";

fn build_preexec_stage_plan() -> [StaticStage; 11] {
    [
        StaticStage {
            name: STAGE_NAMESPACE_SETUP,
            domain: KernelDomain::Namespace,
        },
        StaticStage {
            name: STAGE_MOUNT_HARDENING,
            domain: KernelDomain::Mount,
        },
        StaticStage {
            name: STAGE_CGROUP_ATTACH,
            domain: KernelDomain::Cgroup,
        },
        StaticStage {
            name: STAGE_MOUNT_ROOT_TRANSITION,
            domain: KernelDomain::Cgroup,
        },
        StaticStage {
            name: STAGE_RUNTIME_HYGIENE,
            domain: KernelDomain::Cgroup,
        },
        StaticStage {
            name: STAGE_CREDENTIALS,
            domain: KernelDomain::Credentials,
        },
        StaticStage {
            name: STAGE_CAPABILITIES,
            domain: KernelDomain::Capabilities,
        },
        StaticStage {
            name: STAGE_SIGNAL_HANDOFF,
            domain: KernelDomain::Signal,
        },
        StaticStage {
            name: STAGE_SESSION_LEADERSHIP,
            domain: KernelDomain::Cleanup,
        },
        StaticStage {
            name: STAGE_EVIDENCE,
            domain: KernelDomain::Evidence,
        },
        StaticStage {
            name: STAGE_SECCOMP,
            domain: KernelDomain::Seccomp,
        },
    ]
}

fn validate_preexec_stage_plan(mode: EnforcementMode) -> Result<Vec<&'static str>> {
    let stages = build_preexec_stage_plan();
    let mut pipeline = KernelPipeline::new(mode);
    for stage in &stages {
        pipeline.push_stage(stage);
    }
    pipeline.validate_order()?;
    pipeline.validate_required_domains()?;
    Ok(stages.iter().map(|stage| stage.name).collect())
}

fn verify_parent_death_signal(mode: EnforcementMode) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut signal: libc::c_int = 0;
        // SAFETY: PR_GET_PDEATHSIG writes an integer into a valid mutable pointer.
        let rc = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal as *mut libc::c_int) };
        if rc != 0 {
            return match mode {
                EnforcementMode::Strict => {
                    let message = format!(
                        "failed to verify PR_GET_PDEATHSIG: {}",
                        std::io::Error::last_os_error()
                    );
                    Err(IsolateError::Process(message))
                }
                EnforcementMode::Permissive => {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                        &mut ebuf,
                    );
                    fs_warn_parts(&[
                        "failed to verify PR_GET_PDEATHSIG: errno=",
                        eno,
                        " (permissive mode)",
                    ]);
                    Ok(())
                }
            };
        }

        if signal == libc::SIGKILL {
            return Ok(());
        }

        match mode {
            EnforcementMode::Strict => {
                let message = format!(
                    "unexpected parent death signal {} (expected SIGKILL={})",
                    signal,
                    libc::SIGKILL
                );
                Err(IsolateError::Process(message))
            }
            EnforcementMode::Permissive => {
                let mut sbuf = [0u8; 20];
                let sig = itoa_i32(signal, &mut sbuf);
                let mut kbuf = [0u8; 20];
                let kill = itoa_i32(libc::SIGKILL, &mut kbuf);
                fs_warn_parts(&[
                    "unexpected parent death signal ",
                    sig,
                    " (expected SIGKILL=",
                    kill,
                    ") (permissive mode)",
                ]);
                Ok(())
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        match mode {
            EnforcementMode::Strict => Err(IsolateError::Process(
                "parent death signal verification is only supported on Linux".to_string(),
            )),
            EnforcementMode::Permissive => {
                fs_warn_parts(&["Skipping parent death signal verification on non-Linux platform"]);
                Ok(())
            }
        }
    }
}

fn verify_session_leadership(mode: EnforcementMode) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getpid/getsid are thread-safe libc queries for current process.
        let pid = unsafe { libc::getpid() };
        // SAFETY: getsid(0) queries current process session id.
        let sid = unsafe { libc::getsid(0) };

        if sid < 0 {
            return match mode {
                EnforcementMode::Strict => {
                    let message = format!(
                        "failed to verify cleanup handoff session id: {}",
                        std::io::Error::last_os_error()
                    );
                    Err(IsolateError::Process(message))
                }
                EnforcementMode::Permissive => {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                        &mut ebuf,
                    );
                    fs_warn_parts(&[
                        "failed to verify cleanup handoff session id: errno=",
                        eno,
                        " (permissive mode)",
                    ]);
                    Ok(())
                }
            };
        }

        if sid == pid {
            return Ok(());
        }

        match mode {
            EnforcementMode::Strict => {
                let message = format!(
                    "cleanup handoff requires child session leadership (pid={}, sid={})",
                    pid, sid
                );
                Err(IsolateError::Process(message))
            }
            EnforcementMode::Permissive => {
                let mut pbuf = [0u8; 20];
                let pid_s = itoa_i32(pid, &mut pbuf);
                let mut sbuf = [0u8; 20];
                let sid_s = itoa_i32(sid, &mut sbuf);
                fs_warn_parts(&[
                    "cleanup handoff requires child session leadership (pid=",
                    pid_s,
                    ", sid=",
                    sid_s,
                    ") (permissive mode)",
                ]);
                Ok(())
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        match mode {
            EnforcementMode::Strict => Err(IsolateError::Process(
                "cleanup handoff verification is only supported on Linux".to_string(),
            )),
            EnforcementMode::Permissive => {
                fs_warn_parts(&["Skipping cleanup handoff verification on non-Linux platform"]);
                Ok(())
            }
        }
    }
}

fn mark_stage(report: &mut KernelRunReport, stage_name: &'static str) {
    report.applied_stages.push(stage_name);
    report.verified_stages.push(stage_name);
}

fn parse_non_zero_capability_lines(status: &str) -> Vec<String> {
    const REQUIRED_CAP_LINES: [&str; 5] = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"];
    const ZERO_CAPS: &str = "0000000000000000";

    let mut non_zero = Vec::new();
    for line in status.lines() {
        if REQUIRED_CAP_LINES
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            let value = line.split_whitespace().nth(1).unwrap_or_default();
            if value != ZERO_CAPS {
                non_zero.push(line.trim().to_string());
            }
        }
    }
    non_zero
}

fn verify_full_capability_sets(mode: EnforcementMode) -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
        IsolateError::Privilege(format!(
            "Cannot read /proc/self/status for kernel capability verification: {}",
            e
        ))
    })?;

    let non_zero = parse_non_zero_capability_lines(&status);
    if non_zero.is_empty() {
        return Ok(());
    }

    match mode {
        EnforcementMode::Strict => {
            let message = format!(
                "Kernel v2 post-lock capability verification failed: {}",
                non_zero.join(", ")
            );
            Err(IsolateError::Privilege(message))
        }
        EnforcementMode::Permissive => {
            raw_write(b"[WARN] Kernel v2 post-lock capability verification failed: ");
            for (i, entry) in non_zero.iter().enumerate() {
                if i > 0 {
                    raw_write(b", ");
                }
                raw_write(entry.as_bytes());
            }
            raw_write(b" (permissive mode)\n");
            Ok(())
        }
    }
}

pub fn exec_payload(req: &SandboxLaunchRequest) -> Result<()> {
    let mode = if req.profile.strict_mode {
        EnforcementMode::Strict
    } else {
        EnforcementMode::Permissive
    };

    let planned_stages = validate_preexec_stage_plan(mode)?;
    let mut report = KernelRunReport {
        mode,
        applied_stages: Vec::with_capacity(planned_stages.len()),
        verified_stages: Vec::with_capacity(planned_stages.len()),
    };

    {
        let mut buf = [0u8; 20];
        let count = itoa_buf(planned_stages.len() as u64, &mut buf);
        fs_debug_parts(&["kernel preexec contract plan validated: ", count, " stages"]);
    }

    let sandbox = Sandbox::<FreshChild>::new(req.instance_id.clone(), req.profile.strict_mode);
    // Namespace creation handled by supervisor's clone() - don't unshare again
    let sandbox = sandbox.setup_namespaces(false, false, false, false)?;
    mark_stage(&mut report, STAGE_NAMESPACE_SETUP);
    let sandbox = sandbox.harden_mount_propagation()?;
    mark_stage(&mut report, STAGE_MOUNT_HARDENING);
    let cgroup_attach = req.cgroup_attach_path.as_ref().and_then(|p| p.to_str());
    let sandbox = sandbox.attach_to_cgroup(cgroup_attach)?;
    mark_stage(&mut report, STAGE_CGROUP_ATTACH);
    let sandbox = sandbox.setup_mounts_and_root(&req.profile)?;
    mark_stage(&mut report, STAGE_MOUNT_ROOT_TRANSITION);
    let sandbox = sandbox.apply_runtime_hygiene(&req.profile)?;
    mark_stage(&mut report, STAGE_RUNTIME_HYGIENE);
    let sandbox = sandbox.drop_credentials(req.profile.uid, req.profile.gid)?;
    mark_stage(&mut report, STAGE_CREDENTIALS);
    let sandbox = sandbox.lock_privileges()?;
    mark_stage(&mut report, STAGE_CAPABILITIES);

    verify_parent_death_signal(mode)?;
    mark_stage(&mut report, STAGE_SIGNAL_HANDOFF);

    verify_session_leadership(mode)?;
    mark_stage(&mut report, STAGE_SESSION_LEADERSHIP);

    verify_full_capability_sets(mode)?;
    mark_stage(&mut report, STAGE_EVIDENCE);

    let seccomp_policy = if !req.profile.enable_seccomp {
        crate::kernel::seccomp::SeccompPolicy::Disabled
    } else if let Some(ref path) = req.profile.seccomp_policy_file {
        crate::kernel::seccomp::SeccompPolicy::CustomFile(path.clone())
    } else if req.profile.packages_enabled {
        crate::kernel::seccomp::SeccompPolicy::ExecutorDenyList
    } else {
        crate::kernel::seccomp::SeccompPolicy::BuiltinDenyList
    };
    crate::kernel::seccomp::install_filter(&seccomp_policy)?;
    mark_stage(&mut report, STAGE_SECCOMP);

    let sandbox = sandbox.ready_for_exec();
    sandbox.exec_payload(&req.profile.command)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_non_zero_capability_lines, validate_preexec_stage_plan, STAGE_SECCOMP,
        STAGE_SESSION_LEADERSHIP,
    };
    use crate::kernel::EnforcementMode;

    #[test]
    fn parser_reports_non_zero_sets_including_bounding_and_ambient() {
        let status = "\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000001\n\
CapAmb:\t0000000000000000\n";

        let non_zero = parse_non_zero_capability_lines(status);
        assert_eq!(non_zero, vec!["CapBnd:\t0000000000000001"]);
    }

    #[test]
    fn parser_accepts_all_zero_sets() {
        let status = "\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n";
        let non_zero = parse_non_zero_capability_lines(status);
        assert!(non_zero.is_empty());
    }

    #[test]
    fn preexec_contract_pipeline_is_valid() {
        let stages = validate_preexec_stage_plan(EnforcementMode::Strict)
            .expect("preexec stage contract should validate");
        assert_eq!(stages.len(), 11);
        assert!(stages.contains(&STAGE_SESSION_LEADERSHIP));
        assert!(stages.contains(&STAGE_SECCOMP));
    }
}
