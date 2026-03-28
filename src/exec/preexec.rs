use crate::config::constants;
use crate::config::types::{IsolateError, Result};
use crate::kernel::capabilities::{self, check_no_new_privs, set_no_new_privs};
use crate::kernel::credentials::transition_to_unprivileged;
use crate::sandbox::types::ExecutionProfile;
use crate::utils::fork_safe_log::{fs_debug, fs_info_parts, fs_warn_parts, itoa_buf, itoa_i32};
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
    let mut sbuf = [0u8; 20];
    let mut hbuf = [0u8; 20];
    let mut ebuf = [0u8; 20];
    let soft_s = itoa_buf(soft, &mut sbuf);
    let hard_s = itoa_buf(hard, &mut hbuf);
    let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
    if strict_mode {
        fs_warn_parts(&[
            "FATAL: Failed to apply ",
            name,
            "=",
            soft_s,
            " (hard=",
            hard_s,
            "): errno=",
            eno,
        ]);
        Err(IsolateError::Process(
            "rlimit setup failed in strict mode (see stderr)".to_string(),
        ))
    } else {
        fs_warn_parts(&[
            "Failed to apply ",
            name,
            "=",
            soft_s,
            " (hard=",
            hard_s,
            ") in permissive mode: errno=",
            eno,
        ]);
        Ok(())
    }
}

#[cfg(unix)]
fn apply_exec_environment(env_map: &HashMap<String, String>, strict_mode: bool) -> Result<()> {
    let clear_rc = unsafe { libc::clearenv() };
    if clear_rc != 0 {
        let err = std::io::Error::last_os_error();
        let mut ebuf = [0u8; 20];
        let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
        if strict_mode {
            fs_warn_parts(&["FATAL: clearenv failed: errno=", eno]);
            return Err(IsolateError::Process(
                "clearenv failed in strict mode (see stderr)".to_string(),
            ));
        }
        fs_warn_parts(&["clearenv failed in permissive mode: errno=", eno]);
    }

    for (key, value) in env_map {
        let key_c = match CString::new(key.as_str()) {
            Ok(k) => k,
            Err(_) if strict_mode => {
                fs_warn_parts(&["FATAL: env key contains NUL byte: ", key]);
                return Err(IsolateError::Config(
                    "environment key contains NUL byte (see stderr)".to_string(),
                ));
            }
            Err(_) => {
                fs_warn_parts(&[
                    "Skipping environment key with NUL byte in permissive mode: ",
                    key,
                ]);
                continue;
            }
        };

        let value_c = match CString::new(value.as_str()) {
            Ok(v) => v,
            Err(_) if strict_mode => {
                fs_warn_parts(&["FATAL: env value contains NUL byte for key: ", key]);
                return Err(IsolateError::Config(
                    "environment value contains NUL byte (see stderr)".to_string(),
                ));
            }
            Err(_) => {
                fs_warn_parts(&[
                    "Skipping environment value with NUL byte in permissive mode: ",
                    key,
                ]);
                continue;
            }
        };

        let rc = unsafe { libc::setenv(key_c.as_ptr(), value_c.as_ptr(), 1) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            let mut ebuf = [0u8; 20];
            let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
            if strict_mode {
                fs_warn_parts(&["FATAL: setenv failed for ", key, ": errno=", eno]);
                return Err(IsolateError::Process(
                    "setenv failed in strict mode (see stderr)".to_string(),
                ));
            }
            fs_warn_parts(&[
                "setenv failed for ",
                key,
                " in permissive mode: errno=",
                eno,
            ]);
        }
    }

    Ok(())
}

pub fn setup_parent_death_signal() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::prctl;
        use nix::sys::signal::Signal;

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

pub struct FreshChild;
pub struct NamespacesReady;
pub struct MountsPrivate;
pub struct CgroupAttached;
pub struct RootTransitioned;
pub struct HygieneApplied;
pub struct CredsDropped;
pub struct PrivsLocked;
pub struct ExecReady;

pub struct Sandbox<S> {
    pub pid: Option<u32>,
    pub instance_id: String,
    pub strict_mode: bool,
    pub mount_namespace_enabled: bool,
    _state: PhantomData<S>,
}

impl<S> Sandbox<S> {
    fn transition<T>(self) -> Sandbox<T> {
        Sandbox {
            pid: self.pid,
            instance_id: self.instance_id,
            strict_mode: self.strict_mode,
            mount_namespace_enabled: self.mount_namespace_enabled,
            _state: PhantomData,
        }
    }
}

impl Sandbox<FreshChild> {
    pub fn new(instance_id: String, strict_mode: bool) -> Self {
        Self {
            pid: None,
            instance_id,
            strict_mode,
            mount_namespace_enabled: false,
            _state: PhantomData,
        }
    }

    pub fn setup_namespaces(
        self,
        enable_pid: bool,
        enable_mount: bool,
        enable_network: bool,
        enable_user: bool,
    ) -> Result<Sandbox<NamespacesReady>> {
        use crate::kernel::namespace::NamespaceIsolation;

        #[cfg(target_os = "linux")]
        {
            let sid = unsafe { libc::setsid() };
            if sid < 0 {
                let err = std::io::Error::last_os_error();
                if self.strict_mode {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                    fs_warn_parts(&["FATAL: setsid failed: errno=", eno]);
                    return Err(IsolateError::Process(
                        "setsid failed in strict mode (see stderr)".to_string(),
                    ));
                }
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(err.raw_os_error().unwrap_or(-1), &mut ebuf);
                fs_warn_parts(&["setsid failed in permissive mode: errno=", eno]);
            }
        }

        setup_parent_death_signal()?;

        let ns_isolation = NamespaceIsolation::new(
            enable_pid,
            enable_mount,
            enable_network,
            enable_user,
            false,
            false,
        );

        if ns_isolation.is_isolation_enabled() {
            if let Err(e) = ns_isolation.apply_isolation() {
                if self.strict_mode {
                    return Err(e);
                }
                fs_warn_parts(&["Namespace isolation failed in permissive mode"]);
            } else {
                let ns_list = ns_isolation.get_enabled_namespaces();
                let mut parts: [&str; 14] = [""; 14];
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

        let mut next: Sandbox<NamespacesReady> = self.transition();
        next.mount_namespace_enabled = enable_mount;
        Ok(next)
    }
}

impl Sandbox<NamespacesReady> {
    pub fn harden_mount_propagation(self) -> Result<Sandbox<MountsPrivate>> {
        use crate::kernel::namespace::harden_mount_propagation;

        if self.mount_namespace_enabled {
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

        Ok(self.transition())
    }
}

impl Sandbox<MountsPrivate> {
    pub fn attach_to_cgroup(self, cgroup_path: Option<&str>) -> Result<Sandbox<CgroupAttached>> {
        if let Some(path) = cgroup_path {
            let current_pid = unsafe { libc::getpid() as u32 };
            let cgroup_dir = Path::new(path);
            let pid_text = current_pid.to_string();

            let cgroup_procs = cgroup_dir.join("cgroup.procs");
            let tasks = cgroup_dir.join("tasks");

            let write_result = if cgroup_procs.exists() {
                std::fs::write(&cgroup_procs, &pid_text)
            } else if tasks.exists() {
                std::fs::write(&tasks, &pid_text)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no cgroup.procs or tasks file found",
                ))
            };

            if let Err(e) = write_result {
                if self.strict_mode {
                    let mut pbuf = [0u8; 20];
                    let pid_s = itoa_buf(current_pid as u64, &mut pbuf);
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                    fs_warn_parts(&[
                        "FATAL: cgroup attach PID ",
                        pid_s,
                        " to ",
                        path,
                        ": errno=",
                        eno,
                    ]);
                    return Err(IsolateError::Cgroup(
                        "cgroup attach failed in strict mode (see stderr)".to_string(),
                    ));
                }
                let mut pbuf = [0u8; 20];
                let pid_s = itoa_buf(current_pid as u64, &mut pbuf);
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                let path_s = path;
                fs_warn_parts(&[
                    "Failed to attach PID ",
                    pid_s,
                    " to cgroup ",
                    path_s,
                    " (permissive mode): errno=",
                    eno,
                ]);
            } else {
                let mut pbuf = [0u8; 20];
                let pid_s = itoa_buf(current_pid as u64, &mut pbuf);
                let path_s = path;
                fs_info_parts(&[
                    "Attached PID ",
                    pid_s,
                    " to cgroup ",
                    path_s,
                    " before exec",
                ]);
            }
        }

        Ok(self.transition())
    }
}

impl Sandbox<CgroupAttached> {
    pub fn setup_mounts_and_root(
        self,
        profile: &ExecutionProfile,
    ) -> Result<Sandbox<RootTransitioned>> {
        let mut fs_security = crate::kernel::mount::FilesystemSecurity::new(
            profile.chroot_dir.clone(),
            profile.workdir.clone(),
            self.strict_mode,
            profile
                .tmpfs_size_bytes
                .or(profile.file_size_limit)
                .or(profile.memory_limit),
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

        if profile.packages_enabled {
            if let Err(e) = fs_security.mount_packages() {
                if self.strict_mode {
                    return Err(e);
                }
                fs_warn_parts(&["Package mount failed (permissive mode)"]);
            }
        }

        if let Err(e) = fs_security.apply_chroot() {
            if self.strict_mode {
                return Err(e);
            }
            fs_warn_parts(&["Root transition failed (permissive mode)"]);
        }

        Ok(self.transition())
    }
}

impl Sandbox<RootTransitioned> {
    pub fn apply_runtime_hygiene(
        self,
        profile: &ExecutionProfile,
    ) -> Result<Sandbox<HygieneApplied>> {
        #[cfg(unix)]
        {
            let rlimits: &[(&str, libc::__rlimit_resource_t, Option<(u64, u64)>)] = &[
                (
                    "RLIMIT_AS",
                    libc::RLIMIT_AS,
                    profile.virtual_memory_limit.map(|v| (v, v)),
                ),
                (
                    "RLIMIT_FSIZE",
                    libc::RLIMIT_FSIZE,
                    profile.file_size_limit.map(|v| (v, v)),
                ),
                (
                    "RLIMIT_CORE",
                    libc::RLIMIT_CORE,
                    Some((
                        profile.core_limit.unwrap_or(0),
                        profile.core_limit.unwrap_or(0),
                    )),
                ),
                ("RLIMIT_MEMLOCK", libc::RLIMIT_MEMLOCK, Some((0, 0))),
                (
                    "RLIMIT_NPROC",
                    libc::RLIMIT_NPROC,
                    profile.process_limit.map(|v| (v as u64, v as u64)),
                ),
                (
                    "RLIMIT_STACK",
                    libc::RLIMIT_STACK,
                    profile.stack_limit.map(|v| (v, v)),
                ),
                (
                    "RLIMIT_NOFILE",
                    libc::RLIMIT_NOFILE,
                    profile.fd_limit.map(|v| (v, v)),
                ),
            ];
            for &(name, resource, ref limits) in rlimits {
                if let Some((soft, hard)) = *limits {
                    apply_rlimit_value(name, resource, soft, hard, self.strict_mode)?;
                }
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

            if self.strict_mode || !profile.inherit_fds {
                crate::utils::fd_closure::close_inherited_fds(self.strict_mode)?;
            }

            let mut env_map = hygiene.sanitize_environment()?;
            for (key, value) in &profile.environment {
                env_map.insert(key.clone(), value.clone());
            }
            if profile.packages_enabled {
                env_map.insert(
                    constants::PYTHONPATH_ENV_KEY.to_string(),
                    constants::PYTHONPATH_ENV_VALUE.to_string(),
                );
                env_map.insert(
                    constants::CPP_INCLUDE_ENV_KEY.to_string(),
                    constants::CPP_INCLUDE_ENV_VALUE.to_string(),
                );
                if let Some(existing_cp) = env_map.get("CLASSPATH") {
                    env_map.insert(
                        "CLASSPATH".to_string(),
                        format!("{}:{}", existing_cp, constants::JAVA_CLASSPATH_EXTRA),
                    );
                } else {
                    env_map.insert(
                        "CLASSPATH".to_string(),
                        format!(".:{}", constants::JAVA_CLASSPATH_EXTRA),
                    );
                }
            }

            crate::utils::env_hygiene::strip_dangerous_env(&mut env_map);

            apply_exec_environment(&env_map, self.strict_mode)?;

            if let Err(e) = std::env::set_current_dir(&profile.workdir) {
                if self.strict_mode {
                    let mut ebuf = [0u8; 20];
                    let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                    let wdir = profile.workdir.to_str().unwrap_or("<?>");
                    fs_warn_parts(&["FATAL: chdir to ", wdir, " failed: errno=", eno]);
                    return Err(IsolateError::Config(
                        "chdir to workdir failed in strict mode (see stderr)".to_string(),
                    ));
                }
                let mut ebuf = [0u8; 20];
                let eno = itoa_i32(e.raw_os_error().unwrap_or(-1), &mut ebuf);
                let wdir = profile.workdir.to_str().unwrap_or("<?>");
                fs_warn_parts(&[
                    "Failed to chdir to workdir ",
                    wdir,
                    " (permissive mode): errno=",
                    eno,
                ]);
            }

            capabilities::drop_bounding_and_ambient()?;
        }

        Ok(self.transition())
    }
}

impl Sandbox<HygieneApplied> {
    pub fn drop_credentials(
        self,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<Sandbox<CredsDropped>> {
        match (uid, gid) {
            (Some(uid_val), Some(gid_val)) => {
                transition_to_unprivileged(uid_val, gid_val, self.strict_mode)?;
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(IsolateError::Privilege(
                    "Incomplete credential specification: both uid and gid must be set, \
                     or both must be None. Partial credentials would leave mixed privilege levels."
                        .to_string(),
                ));
            }
            (None, None) => {
                return Err(IsolateError::Privilege(
                    "uid and gid must both be set for credential drop; \
                     running the sandbox as current user is never safe"
                        .to_string(),
                ));
            }
        }

        Ok(self.transition())
    }
}

impl Sandbox<CredsDropped> {
    pub fn lock_privileges(self) -> Result<Sandbox<PrivsLocked>> {
        setup_parent_death_signal()?;

        // SAFETY: PR_SET_DUMPABLE(0) prevents ptrace attach and /proc/pid access
        // from other processes sharing the same UID. Standard sandbox hardening
        // used by Chromium, nsjail, and Firejail.
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            if rc != 0 && self.strict_mode {
                return Err(IsolateError::Privilege(
                    "failed to set PR_SET_DUMPABLE(0)".to_string(),
                ));
            }
        }

        capabilities::drop_process_caps_and_verify(self.strict_mode)?;

        set_no_new_privs()?;
        let is_set = check_no_new_privs()?;
        if !is_set {
            return Err(IsolateError::Privilege(
                "PR_SET_NO_NEW_PRIVS verification failed — this is fatal in all modes \
                 as it is the minimum security floor"
                    .to_string(),
            ));
        }

        Ok(self.transition())
    }
}

impl Sandbox<PrivsLocked> {
    pub fn ready_for_exec(self) -> Sandbox<ExecReady> {
        self.transition()
    }
}

impl Sandbox<ExecReady> {
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

    fn test_profile() -> ExecutionProfile {
        ExecutionProfile {
            command: vec![],
            stdin_data: None,
            environment: vec![],
            inherit_fds: true,
            workdir: std::env::temp_dir(),
            chroot_dir: None,
            uid: None,
            gid: None,
            strict_mode: false,
            enable_pid_namespace: false,
            enable_mount_namespace: false,
            enable_network_namespace: false,
            enable_user_namespace: false,
            memory_limit: None,
            file_size_limit: None,
            stack_limit: None,
            core_limit: None,
            process_limit: None,
            cpu_time_limit_ms: None,
            wall_time_limit_ms: None,
            fd_limit: None,
            virtual_memory_limit: None,
            directory_bindings: vec![],
            enable_seccomp: false,
            seccomp_policy_file: None,
            tmpfs_size_bytes: None,
            pipe_buffer_size: None,
            output_limit: None,
            packages_enabled: false,
            network_enabled: false,
            net_egress_bytes: 0,
            net_ingress_bytes: 0,
            dns_servers: vec![],
            sandbox_ip: None,
            sandbox_cidr: None,
            gateway_ip: None,
            veth_sandbox_name: None,
        }
    }

    #[test]
    fn test_typestate_chain_happy_path() {
        if unsafe { libc::geteuid() } == 0 {
            use nix::sys::wait::{waitpid, WaitStatus};
            use nix::unistd::{fork, ForkResult};
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    run_typestate_chain_happy_path();
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => return,
                    Ok(WaitStatus::Exited(_, code)) => {
                        panic!("typestate happy path child exited with code {}", code)
                    }
                    Ok(status) => panic!("typestate happy path child: {:?}", status),
                    Err(e) => panic!("waitpid failed: {}", e),
                },
                Err(_) => return,
            }
        } else {
            run_typestate_chain_happy_path();
        }
    }

    fn run_typestate_chain_happy_path() {
        let sandbox = Sandbox::<FreshChild>::new("test-001".to_string(), false);

        let Ok(sandbox) = sandbox.setup_namespaces(false, false, false, false) else {
            return;
        };

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return,
        };

        let sandbox = sandbox
            .attach_to_cgroup(None)
            .expect("cgroup attach failed");

        let profile = test_profile();
        let sandbox = sandbox
            .setup_mounts_and_root(&profile)
            .expect("mount root transition failed");

        let sandbox = match sandbox.apply_runtime_hygiene(&profile) {
            Ok(s) => s,
            Err(_) => return,
        };

        let sandbox = sandbox
            .drop_credentials(
                Some(crate::config::constants::NOBODY_UID),
                Some(crate::config::constants::NOBODY_GID),
            )
            .expect("credential drop failed");

        let sandbox = sandbox.lock_privileges().expect("privilege lock failed");

        let sandbox = sandbox.ready_for_exec();

        let _ready = sandbox;
    }

    #[test]
    fn test_exec_payload_rejects_empty_command() {
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
        let profile = test_profile();
        let root = cgroup.setup_mounts_and_root(&profile).expect("mount root");
        let hygiene = match root.apply_runtime_hygiene(&profile) {
            Ok(s) => s,
            Err(_) => return,
        };
        let creds = hygiene
            .drop_credentials(
                Some(crate::config::constants::NOBODY_UID),
                Some(crate::config::constants::NOBODY_GID),
            )
            .expect("drop_credentials");
        let privs = match creds.lock_privileges() {
            Ok(s) => s,
            Err(_) => return,
        };
        let ready = privs.ready_for_exec();

        let result = ready.exec_payload(&[]);
        assert!(result.is_err(), "exec_payload must reject empty command");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("Empty"),
            "expected 'Empty' in error, got: {}",
            msg
        );
    }

    #[test]
    fn test_typestate_chain_preserves_metadata() {
        let sandbox = Sandbox::<FreshChild>::new("test-004".to_string(), true);

        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);

        let sandbox = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return,
        };
        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return,
        };
        assert_eq!(sandbox.instance_id, "test-004");
        assert!(sandbox.strict_mode);
    }

    #[test]
    fn test_typestate_consumes_previous_state() {
        let sandbox = Sandbox::<FreshChild>::new("test-005".to_string(), false);

        let _sandbox2 = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return,
        };
    }

    #[test]
    fn test_typestate_metadata_only() {
        let sandbox = Sandbox::<FreshChild>::new("test-006".to_string(), true);

        assert_eq!(sandbox.instance_id, "test-006");
        assert!(sandbox.strict_mode);
        assert_eq!(sandbox.pid, None);
    }

    #[test]
    fn test_credential_drop_ordering() {
        // Credential drop + lock_privileges is irreversible (setresuid, NO_NEW_PRIVS).
        // When running as root, fork a child so the parent process keeps its privileges
        // for subsequent tests.
        if unsafe { libc::geteuid() } == 0 {
            use nix::sys::wait::{waitpid, WaitStatus};
            use nix::unistd::{fork, ForkResult};
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    run_credential_drop_test();
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => return,
                    Ok(WaitStatus::Exited(_, code)) => {
                        panic!("credential drop test child exited with code {}", code)
                    }
                    Ok(status) => panic!("credential drop test child: {:?}", status),
                    Err(e) => panic!("waitpid failed: {}", e),
                },
                Err(_) => return,
            }
        } else {
            run_credential_drop_test();
        }
    }

    fn run_credential_drop_test() {
        let sandbox = Sandbox::<FreshChild>::new("test-007".to_string(), false);

        let sandbox = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return,
        };

        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return,
        };

        let sandbox = sandbox
            .attach_to_cgroup(None)
            .expect("cgroup attach failed");

        let profile = test_profile();
        let sandbox = sandbox
            .setup_mounts_and_root(&profile)
            .expect("mount root transition failed");

        let sandbox = match sandbox.apply_runtime_hygiene(&profile) {
            Ok(s) => s,
            Err(_) => return,
        };

        let sandbox = sandbox
            .drop_credentials(Some(1000), Some(1000))
            .expect("credential drop failed");

        let sandbox = sandbox.lock_privileges().expect("privilege lock failed");

        let _sandbox = sandbox.ready_for_exec();
    }

    #[test]
    fn test_credential_drop_rejects_none_none() {
        let sandbox = Sandbox::<FreshChild>::new("test-008".to_string(), false);
        let sandbox = match sandbox.setup_namespaces(false, false, false, false) {
            Ok(s) => s,
            Err(_) => return,
        };
        let sandbox = match sandbox.harden_mount_propagation() {
            Ok(s) => s,
            Err(_) => return,
        };
        let sandbox = sandbox.attach_to_cgroup(None).expect("cgroup attach");
        let profile = test_profile();
        let sandbox = sandbox
            .setup_mounts_and_root(&profile)
            .expect("mount root transition");
        let sandbox = match sandbox.apply_runtime_hygiene(&profile) {
            Ok(s) => s,
            Err(_) => return,
        };

        let result = sandbox.drop_credentials(None, None);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("drop_credentials(None, None) must be rejected"),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("uid and gid must both be set"),
            "expected credential error, got: {}",
            msg
        );
    }
}
