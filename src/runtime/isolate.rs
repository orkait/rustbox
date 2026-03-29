use crate::config::types::{ExecutionResult, IsolateConfig, IsolateError, Result};
use crate::config::validator::validate_config;
use crate::kernel::cgroup::{self, CgroupBackend};
use crate::observability::audit::events;
use crate::runtime::security::command_validation;
use crate::safety::uid_pool;
use crate::sandbox::types::{LaunchEvidence, SandboxLaunchRequest};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct ExecutionOverrides {
    pub stdin_data: Option<String>,
    pub max_cpu: Option<u64>,
    pub max_memory: Option<u64>,
    pub max_time: Option<u64>,
    pub max_wall_time: Option<u64>,
    pub fd_limit: Option<u64>,
    pub process_limit: Option<u32>,
}

pub(crate) fn apply_overrides_to_config(
    base: &IsolateConfig,
    overrides: &ExecutionOverrides,
) -> IsolateConfig {
    let mut config = base.clone();
    if let Some(v) = overrides.max_cpu {
        config.cpu_time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.max_memory {
        config.memory_limit = Some(v * crate::config::constants::MB);
    }
    if let Some(v) = overrides.max_time {
        config.cpu_time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.max_wall_time {
        config.wall_time_limit = Some(Duration::from_secs(v));
    }
    if let Some(v) = overrides.fd_limit {
        config.fd_limit = Some(v);
    }
    if let Some(v) = overrides.process_limit {
        config.process_limit = Some(v);
    }
    config
}

pub struct Isolate {
    config: IsolateConfig,
    base_path: PathBuf,
    cgroup: Option<Box<dyn CgroupBackend>>,
    last_launch_evidence: Option<LaunchEvidence>,
    _uid_guard: Option<uid_pool::UidGuard>,
}

impl Isolate {
    fn select_state_root() -> Result<PathBuf> {
        let candidates = vec![
            IsolateConfig::runtime_root_dir(),
            std::env::temp_dir().join("rustbox"),
        ];
        for candidate in &candidates {
            if fs::create_dir_all(candidate).is_ok() {
                return Ok(candidate.clone());
            }
        }
        Err(IsolateError::Config(
            "No writable state root available".to_string(),
        ))
    }

    /// Allocate all resources. Nothing else allocates after this.
    /// On failure, cleans up any partially-created state (directory, cgroup).
    pub fn new(mut config: IsolateConfig) -> Result<Self> {
        let uid_guard = uid_pool::UidGuard::allocate()?;
        let pool_uid = uid_guard.uid();
        config.uid = Some(pool_uid);
        config.gid = Some(pool_uid);
        config.instance_id = format!("rustbox/{}", pool_uid);

        if config.strict_mode && unsafe { libc::geteuid() } != 0 {
            return Err(IsolateError::Privilege(
                "Strict mode requires root".to_string(),
            ));
        }

        let validation = validate_config(&config)?;
        for warning in validation.warnings {
            log::warn!("Config: {}", warning);
        }

        let mut base_path = Self::select_state_root()?;
        base_path.push(pool_uid.to_string());
        fs::create_dir_all(&base_path)?;

        let cgroup = match cgroup::select_cgroup_backend(config.strict_mode, &config.instance_id) {
            Ok(cg) => match cg.create(&config.instance_id) {
                Ok(()) => {
                    if let Some(mem) = config.memory_limit {
                        if let Err(e) = cg.set_memory_limit(&config.instance_id, mem) {
                            let _ = cg.remove(&config.instance_id);
                            let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                            return Err(e);
                        }
                    }
                    if let Some(procs) = config.process_limit {
                        if let Err(e) = cg.set_process_limit(&config.instance_id, procs) {
                            let _ = cg.remove(&config.instance_id);
                            let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                            return Err(e);
                        }
                    }
                    Some(cg)
                }
                Err(e) if config.strict_mode => {
                    let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                    return Err(e);
                }
                Err(_) => None,
            },
            Err(e) if config.strict_mode => {
                let _ = crate::safety::safe_cleanup::remove_tree_secure(&base_path);
                return Err(e);
            }
            Err(_) => None,
        };

        let workdir = base_path.join("workdir");
        fs::create_dir_all(&workdir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &workdir,
                fs::Permissions::from_mode(crate::config::constants::PERM_DIR_STANDARD),
            )?;
            if unsafe { libc::geteuid() } == 0 {
                if let (Some(uid), Some(gid)) = (config.uid, config.gid) {
                    use nix::unistd::{chown, Gid, Uid};
                    chown(&workdir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
                        .map_err(|e| IsolateError::Config(format!("chown workdir: {}", e)))?;
                }
            }
        }
        config.workdir = workdir;

        Ok(Self {
            config,
            base_path,
            cgroup,
            last_launch_evidence: None,
            _uid_guard: Some(uid_guard),
        })
    }

    pub fn execute(
        &mut self,
        command: &[String],
        stdin_data: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_with_overrides(
            command,
            &ExecutionOverrides {
                stdin_data: stdin_data.map(str::to_string),
                ..Default::default()
            },
        )
    }

    /// Pure execution. No allocation, no deallocation.
    pub fn execute_with_overrides(
        &mut self,
        command: &[String],
        overrides: &ExecutionOverrides,
    ) -> Result<ExecutionResult> {
        let config = apply_overrides_to_config(&self.config, overrides);

        if command.is_empty() {
            return Err(IsolateError::Config("Empty command".to_string()));
        }

        let validated = match command_validation::validate_and_resolve_command(&command[0]) {
            Ok(path) => path,
            Err(e) => {
                events::command_injection_attempt(&command[0], None);
                return Err(e);
            }
        };
        let mut argv = vec![validated.to_string_lossy().to_string()];
        argv.extend(command.iter().skip(1).cloned());

        if self.cgroup.is_none() && config.strict_mode {
            return Err(IsolateError::Cgroup(
                "No cgroup backend for strict mode".to_string(),
            ));
        }

        let request = SandboxLaunchRequest::from_config(
            &config,
            &argv,
            overrides.stdin_data.as_deref(),
            self.cgroup
                .as_ref()
                .map(|cg| cg.get_cgroup_path(&config.instance_id)),
        );

        let outcome =
            crate::sandbox::supervisor::launch_with_supervisor(request, self.cgroup.as_deref())?;

        self.last_launch_evidence = Some(outcome.evidence);
        Ok(outcome.result)
    }

    pub(crate) fn wipe_workdir(&self) -> bool {
        let workdir = &self.config.workdir;
        if workdir.as_os_str().is_empty() || !workdir.exists() {
            return true;
        }
        let entries = match fs::read_dir(workdir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("wipe_workdir: cannot read {}: {}", workdir.display(), e);
                return false;
            }
        };
        let mut clean = true;
        for entry in entries.flatten() {
            let path = entry.path();
            let result = if path.is_dir() && !path.is_symlink() {
                crate::safety::safe_cleanup::remove_tree_secure(&path)
            } else {
                fs::remove_file(&path).map_err(|e| {
                    crate::config::types::IsolateError::Filesystem(format!(
                        "remove {}: {}",
                        path.display(),
                        e
                    ))
                })
            };
            if let Err(e) = result {
                log::warn!("wipe_workdir: failed to remove {}: {}", path.display(), e);
                clean = false;
            }
        }
        clean
    }

    /// Deallocate everything. Only place that frees resources.
    pub fn cleanup(mut self) -> Result<()> {
        if let Some(cg) = self.cgroup.take() {
            let _ = cg.remove(&self.config.instance_id);
        }
        if self.base_path.exists() {
            let _ = crate::safety::safe_cleanup::remove_tree_secure(&self.base_path);
        }
        drop(self._uid_guard.take());
        Ok(())
    }

    pub(crate) fn update_cgroup_limits(&self) {
        if let Some(ref cg) = self.cgroup {
            if let Some(mem) = self.config.memory_limit {
                let _ = cg.set_memory_limit(&self.config.instance_id, mem);
            }
            if let Some(procs) = self.config.process_limit {
                let _ = cg.set_process_limit(&self.config.instance_id, procs);
            }
        }
    }

    pub fn config(&self) -> &IsolateConfig {
        &self.config
    }
    pub fn config_mut(&mut self) -> &mut IsolateConfig {
        &mut self.config
    }
    pub fn take_last_launch_evidence(&mut self) -> Option<LaunchEvidence> {
        self.last_launch_evidence.take()
    }
}

impl Drop for Isolate {
    fn drop(&mut self) {
        self.wipe_workdir();
        if let Some(cg) = self.cgroup.take() {
            let _ = cg.remove(&self.config.instance_id);
        }
        if self.base_path.exists() {
            let _ = crate::safety::safe_cleanup::remove_tree_secure(&self.base_path);
        }
    }
}
