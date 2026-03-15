use crate::config::types::{IsolateError, Result};
use crate::core::types::ExecutionProfile;
use crate::utils::fork_safe_log::{
    fs_debug, fs_info_parts, fs_warn_parts, itoa_buf, itoa_i32,
};
/// Pre-Exec Ordering Enforcement
/// Implements P1-ORDER-001: Locked Pre-Exec Ordering Enforcement
/// Per plan.md Section 6: Locked Pre-Exec Sequence
///
/// The setup sequence is FIXED and must not drift:
/// 1. setsid() and lifecycle ownership setup
/// 2. prctl(PR_SET_PDEATHSIG, SIGKILL) for child/sandbox-init
/// 3. namespace setup (unshare flags as configured)
/// 4. mount propagation hardening: set / to MS_PRIVATE | MS_REC immediately
/// 5. mount/bind setup and root transition (pivot_root preferred, chroot fallback)
/// 6. if user namespace enabled: setgroups handling, uid_map, gid_map
/// 7. apply rlimit set, umask, FD closure, and env sanitization
/// 8. drop capabilities (bounding and ambient/effective/permitted/inheritable)
/// 9. setresgid then setresuid
/// 10. prctl(PR_SET_NO_NEW_PRIVS, 1)
/// 11. exec payload
use crate::kernel::capabilities::{self, check_no_new_privs, set_no_new_privs};
use crate::kernel::credentials::transition_to_unprivileged;
use std::collections::HashMap;
use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;

#[cfg(unix)]
fn apply_rlimit_value(
    name: &str,
    resource: libc::__rlimit_resource_t,
    soft: u64,
    hard: u64,
    strict_mode: bool,
) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };

    let rc = unsafe { libc::setrlimit(resource, &limit) };
    if rc == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if strict_mode {
        Err(IsolateError::Process(format!(
            "Failed to apply {}={} (hard={}): {}",
            name, soft, hard, err
        )))
    } else {
        let mut sbuf = [0u8; 20];
        let mut hbuf = [0u8; 20];
        let mut ebuf = [0u8; 20];
        let soft_s = itoa_buf(soft, &mut sbuf);
        let hard_s = itoa_buf(hard, &mut hbuf);
        let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
        fs_warn_parts(&[
            "Failed to apply ", name, "=", soft_s, " (hard=", hard_s,
            ") in permissive mode: errno=", eno,
        ]);
        Ok(())
    }
}

#[cfg(unix)]
fn apply_exec_environment(env_map: &HashMap<String, String>, strict_mode: bool) -> Result<()> {
    let clear_rc = unsafe { libc::clearenv() };
    if clear_rc != 0 {
        let err = std::io::Error::last_os_error();
        if strict_mode {
            return Err(IsolateError::Process(format!(
                "clearenv failed in strict mode: {}",
                err
            )));
        }
        let mut ebuf = [0u8; 20];
        let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
        fs_warn_parts(&["clearenv failed in permissive mode: errno=", eno]);
    }

    for (key, value) in env_map {
        let key_c = match CString::new(key.as_str()) {
            Ok(k) => k,
            Err(_) if strict_mode => {
                return Err(IsolateError::Config(format!(
                    "Environment key contains NUL byte: {}",
                    key
                )));
            }
            Err(_) => {
                fs_warn_parts(&[
                    "Skipping environment key with NUL byte in permissive mode: ", key,
                ]);
                continue;
            }
        };

        let value_c = match CString::new(value.as_str()) {
            Ok(v) => v,
            Err(_) if strict_mode => {
                return Err(IsolateError::Config(format!(
                    "Environment value for {} contains NUL byte",
                    key
                )));
            }
            Err(_) => {
                fs_warn_parts(&[
                    "Skipping environment value with NUL byte in permissive mode: ", key,
                ]);
                continue;
            }
        };

        let rc = unsafe { libc::setenv(key_c.as_ptr(), value_c.as_ptr(), 1) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if strict_mode {
                return Err(IsolateError::Process(format!(
                    "setenv failed for {}: {}",
                    key, err
                )));
            }
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            fs_warn_parts(&["setenv failed for ", key, " in permissive mode: errno=", eno]);
        }
    }

    Ok(())
}

// ============================================================================
// Parent Death Signal Setup
// ============================================================================

/// Setup parent death signal for child process
/// Per plan.md Section 7: Supervisor death contract
/// Must be called in child process after fork
pub fn setup_parent_death_signal() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::prctl;
        use nix::sys::signal::Signal;

        // Set PR_SET_PDEATHSIG to SIGKILL
        // Child will receive SIGKILL if parent dies
        prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| {
            IsolateError::Process(format!("Failed to set parent death signal: {}", e))
        })?;

        fs_debug("Parent death signal (SIGKILL) configured");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        crate::utils::fork_safe_log::fs_warn("Parent death signal not supported on this platform");
        Ok(())
    }
}

// ============================================================================
// Type-State Pre-Exec Chain (P1-TYPESTATE-001)
// ============================================================================
// Per plan.md Section 6.1: Correct-by-Construction Pre-Exec Contract
//
// Pre-exec must be represented as a type-state chain so illegal orderings
// cannot compile. This implements the state progression:
//
// FreshChild -> NamespacesReady -> MountsPrivate -> CgroupAttached ->
// CredsDropped -> PrivsLocked -> ExecReady
//
// Each step consumes prior state and returns exactly one next state on success.
// Only Sandbox<ExecReady> exposes payload exec.

/// Type-state marker: Fresh child process, no setup done yet
pub struct FreshChild;

/// Type-state marker: Namespaces have been set up
pub struct NamespacesReady;

/// Type-state marker: Mount propagation has been hardened
pub struct MountsPrivate;

/// Type-state marker: Process attached to cgroup
pub struct CgroupAttached;

/// Type-state marker: Credentials have been dropped
pub struct CredsDropped;

/// Type-state marker: Privileges have been locked down
pub struct PrivsLocked;

/// Type-state marker: Ready for exec (all gates passed)
pub struct ExecReady;

/// Sandbox process with type-state tracking
/// The type parameter S tracks which pre-exec state we're in
pub struct Sandbox<S> {
    /// Process ID (if spawned)
    pub pid: Option<u32>,
    /// Instance identifier
    pub instance_id: String,
    /// Strict mode flag
    pub strict_mode: bool,
    /// Whether mount namespace was enabled in setup
    pub mount_namespace_enabled: bool,
    /// Type-state marker (zero-sized)
    _state: PhantomData<S>,
}

impl Sandbox<FreshChild> {
    /// Create a new sandbox in FreshChild state
    pub fn new(instance_id: String, strict_mode: bool) -> Self {
        Self {
            pid: None,
            instance_id,
            strict_mode,
            mount_namespace_enabled: false,
            _state: PhantomData,
        }
    }

    /// Transition to NamespacesReady state
    /// This consumes FreshChild and returns NamespacesReady on success
    pub fn setup_namespaces(
        self,
        enable_pid: bool,
        enable_mount: bool,
        enable_network: bool,
        enable_user: bool,
    ) -> Result<Sandbox<NamespacesReady>> {
        use crate::kernel::namespace::NamespaceIsolation;

        // Step 1: create a new session/process-group for lifecycle isolation.
        #[cfg(target_os = "linux")]
        {
            let sid = unsafe { libc::setsid() };
            if sid < 0 {
                let err = std::io::Error::last_os_error();
                if self.strict_mode {
                    return Err(IsolateError::Process(format!("setsid failed: {}", err)));
                }
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_warn_parts(&["setsid failed in permissive mode: errno=", eno]);
            }
        }

        // Step 2: ensure child dies if supervisor/parent dies.
        setup_parent_death_signal()?;

        let ns_isolation = NamespaceIsolation::new(
            enable_pid,
            enable_mount,
            enable_network,
            enable_user,
            false, // IPC namespace
            false, // UTS namespace
        );

        if ns_isolation.is_isolation_enabled() {
            if let Err(e) = ns_isolation.apply_isolation() {
                if self.strict_mode {
                    return Err(e);
                }
                // e is IsolateError — log a static diagnostic; the error detail
                // was already constructed by apply_isolation and can't be
                // formatted without allocation post-fork.
                fs_warn_parts(&["Namespace isolation failed in permissive mode"]);
            } else {
                // Log each enabled namespace as a separate segment.
                let ns_list = ns_isolation.get_enabled_namespaces();
                let mut parts: [&str; 14] = [""; 14]; // max 6 namespaces * 2 + header + trailer
                parts[0] = "Applied namespace isolation: [";
                let mut idx = 1;
                for (i, ns) in ns_list.iter().enumerate() {
                    if i > 0 {
                        parts[idx] = ", ";
                        idx += 1;
                    }
                    parts[idx] = ns;
                    idx += 1;
                }
                parts[idx] = "]";
                idx += 1;
                fs_info_parts(&parts[..idx]);
            }
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: enable_mount,
            _state: PhantomData,
        })
    }
}

impl Sandbox<NamespacesReady> {
    /// Transition to MountsPrivate state
    /// This hardens mount propagation before any mount operations
    pub fn harden_mount_propagation(self) -> Result<Sandbox<MountsPrivate>> {
        use crate::kernel::namespace::harden_mount_propagation;

        if self.mount_namespace_enabled {
            // Per plan.md Section 6: mount propagation hardening is MANDATORY
            // Failure is fatal in strict mode.
            if let Err(e) = harden_mount_propagation() {
                if self.strict_mode {
                    return Err(e);
                } else {
                    fs_warn_parts(&["Mount propagation hardening failed (permissive mode)"]);
                }
            }
        } else {
            fs_debug("Mount namespace disabled; skipping propagation hardening step");
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        })
    }
}

impl Sandbox<MountsPrivate> {
    /// Transition to CgroupAttached state
    /// This attaches the process to its cgroup before any user code runs
    pub fn attach_to_cgroup(self, cgroup_path: Option<&str>) -> Result<Sandbox<CgroupAttached>> {
        if let Some(path) = cgroup_path {
            let current_pid = unsafe { libc::getpid() as u32 };
            let cgroup_dir = Path::new(path);
            let pid_text = current_pid.to_string();

            // Support both v2 (cgroup.procs) and v1 (tasks) interfaces.
            let cgroup_procs = cgroup_dir.join("cgroup.procs");
            let tasks = cgroup_dir.join("tasks");

            let write_result = if cgroup_procs.exists() {
                std::fs::write(&cgroup_procs, &pid_text)
            } else if tasks.exists() {
                std::fs::write(&tasks, &pid_text)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "No cgroup attach file found under {} (expected cgroup.procs or tasks)",
                        cgroup_dir.display()
                    ),
                ))
            };

            if let Err(e) = write_result {
                if self.strict_mode {
                    return Err(IsolateError::Cgroup(format!(
                        "Failed to attach PID {} to cgroup {}: {}",
                        current_pid,
                        cgroup_dir.display(),
                        e
                    )));
                }
                let mut pbuf = [0u8; 20];
                let pid_s = itoa_buf(current_pid as u64, &mut pbuf);
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                let path_s = path; // already &str from cgroup_path
                fs_warn_parts(&[
                    "Failed to attach PID ", pid_s, " to cgroup ", path_s,
                    " (permissive mode): errno=", eno,
                ]);
            } else {
                let mut pbuf = [0u8; 20];
                let pid_s = itoa_buf(current_pid as u64, &mut pbuf);
                let path_s = path; // already &str from cgroup_path
                fs_info_parts(&["Attached PID ", pid_s, " to cgroup ", path_s, " before exec"]);
            }
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        })
    }
}

impl Sandbox<CgroupAttached> {
    /// Step 5: mount/bind setup and root transition (pivot_root/chroot fallback).
    /// Runs AFTER cgroup attach so host cgroup paths are still visible during attach.
    pub fn setup_mounts_and_root(
        self,
        profile: &ExecutionProfile,
    ) -> Result<Sandbox<CgroupAttached>> {
        let mut fs_security = crate::kernel::mount::FilesystemSecurity::new(
            profile.chroot_dir.clone(),
            profile.workdir.clone(),
            self.strict_mode,
            profile.file_size_limit.or(profile.memory_limit),
            None,
        );

        if let Err(e) = fs_security.setup_isolation() {
            if self.strict_mode {
                return Err(e);
            }
            fs_warn_parts(&["Filesystem isolation setup failed (permissive mode)"]);
        }

        if let Err(e) = fs_security.setup_directory_bindings(&profile.directory_bindings) {
            if self.strict_mode {
                return Err(e);
            }
            fs_warn_parts(&["Directory binding setup failed (permissive mode)"]);
        }

        if let Err(e) = fs_security.apply_chroot() {
            if self.strict_mode {
                return Err(e);
            }
            fs_warn_parts(&["Root transition failed (permissive mode)"]);
        }

        Ok(self)
    }

    /// Apply pre-exec Step 7 in active runtime path:
    /// rlimits, umask, FD closure, and environment sanitization.
    pub fn apply_runtime_hygiene(
        self,
        profile: &ExecutionProfile,
    ) -> Result<Sandbox<CgroupAttached>> {
        #[cfg(unix)]
        {
            // RLIMIT_AS (virtual address space) — per-language defense against
            // mmap(MAP_NORESERVE) VMA exhaustion.  Physical memory is still
            // enforced via cgroup memory.limit_in_bytes.  Java 17+ gets a
            // higher limit (4 GB) to accommodate compressed class pointers.
            if let Some(virtual_mem_limit) = profile.virtual_memory_limit {
                apply_rlimit_value(
                    "RLIMIT_AS",
                    libc::RLIMIT_AS,
                    virtual_mem_limit,
                    virtual_mem_limit,
                    self.strict_mode,
                )?;
            }

            if let Some(file_size_limit) = profile.file_size_limit {
                apply_rlimit_value(
                    "RLIMIT_FSIZE",
                    libc::RLIMIT_FSIZE,
                    file_size_limit,
                    file_size_limit,
                    self.strict_mode,
                )?;
            }

            let core_limit = profile.core_limit.unwrap_or(0);
            apply_rlimit_value(
                "RLIMIT_CORE",
                libc::RLIMIT_CORE,
                core_limit,
                core_limit,
                self.strict_mode,
            )?;

            apply_rlimit_value(
                "RLIMIT_MEMLOCK",
                libc::RLIMIT_MEMLOCK,
                0,
                0,
                self.strict_mode,
            )?;

            if let Some(process_limit) = profile.process_limit {
                let nproc = process_limit as u64;
                apply_rlimit_value(
                    "RLIMIT_NPROC",
                    libc::RLIMIT_NPROC,
                    nproc,
                    nproc,
                    self.strict_mode,
                )?;
            }

            if let Some(stack_limit) = profile.stack_limit {
                apply_rlimit_value(
                    "RLIMIT_STACK",
                    libc::RLIMIT_STACK,
                    stack_limit,
                    stack_limit,
                    self.strict_mode,
                )?;
            }

            if let Some(fd_limit) = profile.fd_limit {
                apply_rlimit_value(
                    "RLIMIT_NOFILE",
                    libc::RLIMIT_NOFILE,
                    fd_limit,
                    fd_limit,
                    self.strict_mode,
                )?;
            }

            // C2: RLIMIT_CPU as defense-in-depth for CPU-time enforcement.
            // soft = limit_secs → SIGXCPU, hard = limit_secs+1 → SIGKILL.
            if let Some(cpu_ms) = profile.cpu_time_limit_ms {
                let cpu_secs = (cpu_ms / 1000).max(1);
                apply_rlimit_value(
                    "RLIMIT_CPU",
                    libc::RLIMIT_CPU,
                    cpu_secs,
                    cpu_secs + 1,
                    self.strict_mode,
                )?;
            }

            let env_policy = crate::utils::env_hygiene::EnvPolicy {
                strict_mode: self.strict_mode,
                ..Default::default()
            };
            let perm_policy = crate::utils::env_hygiene::PermissionPolicy {
                strict_mode: self.strict_mode,
                ..Default::default()
            };
            let hygiene = crate::utils::env_hygiene::EnvHygiene::new(env_policy, perm_policy);

            hygiene.apply_umask()?;

            // Strict mode always closes inherited FDs; permissive/dev may opt in via config.
            if self.strict_mode || !profile.inherit_fds {
                crate::utils::fd_closure::close_inherited_fds(self.strict_mode)?;
            }

            let mut env_map = hygiene.sanitize_environment()?;
            for (key, value) in &profile.environment {
                env_map.insert(key.clone(), value.clone());
            }

            // VULN-002 / VULN-014 FIX: Re-sanitize after merging profile.environment.
            // Profile environment variables from config.json are inserted after the
            // initial sanitize_environment() call, which means dangerous variables
            // like LD_PRELOAD can be re-injected via config. Remove all known
            // dangerous loader and interpreter control variables unconditionally.
            const DANGEROUS_ENV_BLOCKLIST: &[&str] = &[
                // LD_* loader hijack variables (VULN-002)
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "LD_AUDIT",
                "LD_DEBUG",
                "LD_PROFILE",
                "LD_BIND_NOW",
                "LD_BIND_NOT",
                "LD_DYNAMIC_WEAK",
                "LD_USE_LOAD_BIAS",
                // Process-control / interpreter injection variables (VULN-014)
                "BASH_ENV",
                "ENV",
                "CDPATH",
                "PYTHONSTARTUP",
                "PYTHONPATH",
                "PERL5OPT",
                "RUBYOPT",
                "NODE_OPTIONS",
                // Java-specific options injection (VULN-044)
                "JAVA_TOOL_OPTIONS",
                "_JAVA_OPTIONS",
                "JDK_JAVA_OPTIONS",
            ];
            for key in DANGEROUS_ENV_BLOCKLIST {
                if env_map.remove(*key).is_some() {
                    fs_warn_parts(&[
                        "Removed dangerous environment variable after profile merge: ",
                        key,
                    ]);
                }
            }

            apply_exec_environment(&env_map, self.strict_mode)?;

            // Run payload from configured workspace for deterministic relative-path behavior.
            if let Err(e) = std::env::set_current_dir(&profile.workdir) {
                if self.strict_mode {
                    return Err(IsolateError::Config(format!(
                        "Failed to chdir to workdir {}: {}",
                        profile.workdir.display(),
                        e
                    )));
                }
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                let wdir = profile.workdir.to_str().unwrap_or("<?>");
                fs_warn_parts(&[
                    "Failed to chdir to workdir ", wdir, " (permissive mode): errno=", eno,
                ]);
            }

            // Step 8 (partial): drop bounding and ambient capability sets while still
            // effective root. PR_CAPBSET_DROP requires CAP_SETPCAP in the effective set,
            // which is cleared by setresuid (step 9). Must happen here, not in lock_privileges.
            capabilities::drop_bounding_and_ambient()?;
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        })
    }

    /// Transition to CredsDropped state
    /// This drops credentials (setresgid then setresuid)
    /// Per plan.md Section 6: setresgid THEN setresuid (order is critical)
    pub fn drop_credentials(
        self,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<Sandbox<CredsDropped>> {
        // P15-PRIV-003: UID/GID Transition
        // Per plan.md Section 6: setresgid THEN setresuid
        // Order is critical: groups must be set before dropping to unprivileged user

        match (uid, gid) {
            (Some(uid_val), Some(gid_val)) => {
                // Use credentials module for complete transition
                // This handles: setgroups([]), setresgid, setresuid, verification
                // VULN-001 FIX: credential drop is part of the minimum security floor
                // and is fatal in ALL modes, not just strict.
                transition_to_unprivileged(uid_val, gid_val, self.strict_mode)?;
            }
            (Some(_), None) | (None, Some(_)) => {
                // VULN-001 FIX: Partial credential specification is always an error.
                // If only one of uid/gid is set, the transition is incomplete and
                // the process would run with mixed privilege levels.
                return Err(IsolateError::Privilege(
                    "Incomplete credential specification: both uid and gid must be set, \
                     or both must be None. Partial credentials would leave mixed privilege levels."
                        .to_string(),
                ));
            }
            (None, None) => {
                // VULN-001 FIX: No credentials specified — intentional for permissive/dev mode.
                // Log a warning so this is visible in audit trails.
                fs_warn_parts(&[
                    "No uid/gid specified for credential drop; process retains current credentials",
                ]);
            }
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        })
    }
}

impl Sandbox<CredsDropped> {
    /// Transition to PrivsLocked state
    /// This locks down privileges (capabilities + no_new_privs)
    pub fn lock_privileges(self) -> Result<Sandbox<PrivsLocked>> {
        // Re-set PR_SET_PDEATHSIG after credential drop.
        // The kernel clears pdeath_signal whenever EUID/EGID changes (setresuid/setresgid),
        // so the value set in setup_namespaces is gone by this point.
        setup_parent_death_signal()?;

        capabilities::drop_process_caps_and_verify(self.strict_mode)?;

        // VULN-013 FIX: PR_SET_NO_NEW_PRIVS is part of the minimum security floor.
        // It prevents privilege escalation via setuid/setgid binaries and must succeed
        // in ALL modes, not just strict. Without this, an attacker could exec a
        // setuid binary to regain root even after credential drop.
        set_no_new_privs()?;
        let is_set = check_no_new_privs()?;
        if !is_set {
            return Err(IsolateError::Privilege(
                "PR_SET_NO_NEW_PRIVS verification failed — this is fatal in all modes \
                 as it is the minimum security floor"
                    .to_string(),
            ));
        }

        Ok(Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        })
    }
}

impl Sandbox<PrivsLocked> {
    /// Transition to ExecReady state after privilege hardening.
    pub fn ready_for_exec(self) -> Sandbox<ExecReady> {
        Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        }
    }
}

impl Sandbox<ExecReady> {
    /// Execute the payload
    /// This is the ONLY legal way to exec the payload
    /// Per plan.md Section 6.1: Only Sandbox<ExecReady> exposes payload exec
    pub fn exec_payload(self, command: &[String]) -> Result<()> {
        if command.is_empty() {
            return Err(IsolateError::Config("Empty command for exec".to_string()));
        }

        let mut cargv = Vec::with_capacity(command.len());
        for arg in command {
            let c = CString::new(arg.as_str())
                .map_err(|_| IsolateError::Config("command contains NUL byte".to_string()))?;
            cargv.push(c);
        }
        let cargv_ref: Vec<&std::ffi::CStr> = cargv.iter().map(|c| c.as_c_str()).collect();

        nix::unistd::execvp(cargv[0].as_c_str(), &cargv_ref)
            .map_err(|e| IsolateError::Process(format!("execvp failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod typestate_tests {
    use super::*;

    #[test]
    fn test_typestate_chain_happy_path() {
        // Create fresh sandbox
        let sandbox = Sandbox::<FreshChild>::new("test-001".to_string(), false);

        // Progress through states
        // Note: namespace setup will fail without privileges, but that's OK for testing the type system
        let Ok(sandbox) = sandbox.setup_namespaces(false, false, false, false) else {
            // Skip test if we don't have privileges
            // The type-state chain is still validated at compile time
            return;
        };

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };

        let sandbox = sandbox
            .attach_to_cgroup(None)
            .expect("cgroup attach failed");

        let sandbox = sandbox
            .drop_credentials(None, None)
            .expect("credential drop failed");

        let sandbox = sandbox.lock_privileges().expect("privilege lock failed");

        let sandbox = sandbox.ready_for_exec();

        // Reaching ExecReady proves compile-time chain; runtime exec is integration-tested elsewhere.
        let _ready = sandbox;
    }

    #[test]
    fn test_exec_payload_rejects_empty_command() {
        // Reach ExecReady with no namespace/privilege ops (all disabled, permissive).
        let sandbox = Sandbox::<FreshChild>::new("test-003".to_string(), false);
        let ns = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mounts = match ns.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return,
        };
        let cgroup = mounts.attach_to_cgroup(None).expect("cgroup attach");
        let creds = cgroup.drop_credentials(None, None).expect("drop_credentials");
        let privs = match creds.lock_privileges() {
            Ok(s) => s,
            Err(_) => return,
        };
        let ready = privs.ready_for_exec();

        // exec_payload must reject an empty command before issuing execvp.
        let result = ready.exec_payload(&[]);
        assert!(result.is_err(), "exec_payload must reject empty command");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("Empty"), "expected 'Empty' in error, got: {}", msg);
    }

    #[test]
    fn test_typestate_chain_preserves_metadata() {
        let sandbox = Sandbox::<FreshChild>::new("test-004".to_string(), true);

        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);

        // Metadata is preserved through transitions
        // Skip namespace operations that require privileges
        let sandbox = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };
        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };
        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);
    }

    #[test]
    fn test_typestate_consumes_previous_state() {
        let sandbox = Sandbox::<FreshChild>::new("test-005".to_string(), false);

        // After this transition, sandbox is consumed and cannot be used again
        let _sandbox2 = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };

        // The following would not compile:
        // sandbox.setup_namespaces(false, false, false, false); // COMPILE ERROR! sandbox moved
        // Test passes by reaching this point — the type system enforces move semantics.
    }

    #[test]
    fn test_typestate_metadata_only() {
        // Test that doesn't require privileges - just tests the type system
        let sandbox = Sandbox::<FreshChild>::new("test-006".to_string(), true);

        assert_eq!(sandbox.instance_id, "test-006");
        assert!(sandbox.strict_mode);
        assert_eq!(sandbox.pid, None);
    }

    #[test]
    fn test_credential_drop_ordering() {
        // Test that credentials are dropped in correct order (GID then UID)
        // This test verifies the API enforces the correct order

        let sandbox = Sandbox::<FreshChild>::new("test-007".to_string(), false);

        // Progress through states
        let sandbox = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return, // Skip if no privileges
        };

        let sandbox = sandbox
            .attach_to_cgroup(None)
            .expect("cgroup attach failed");

        // Drop credentials with GID and UID
        // The implementation ensures GID is set before UID
        let sandbox = sandbox
            .drop_credentials(Some(1000), Some(1000))
            .expect("credential drop failed");

        // Verify we're in CredsDropped state (type system enforces this)
        let sandbox = sandbox.lock_privileges().expect("privilege lock failed");

        // Verify transition to ExecReady
        let _sandbox = sandbox.ready_for_exec();
    }
}
