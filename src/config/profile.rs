use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::constants;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    Judge,
    Executor,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self::Judge
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileLimits {
    pub wall_time_sec: u64,
    pub cpu_time_sec: u64,
    pub memory_mb: u64,
    pub process_limit: u32,
    pub fd_limit: u64,
    pub file_size_mb: u64,
    pub disk_quota_mb: u64,
    pub network: bool,
    pub packages: bool,
    pub net_egress_mb: u64,
    pub net_ingress_mb: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub defaults: ProfileLimits,
    pub max: ProfileLimits,
}

impl SecurityProfile {
    pub fn hardcoded_defaults(&self) -> ProfileLimits {
        match self {
            Self::Judge => ProfileLimits {
                wall_time_sec: constants::DEFAULT_WALL_TIME_LIMIT.as_secs(),
                cpu_time_sec: constants::DEFAULT_CPU_TIME_LIMIT.as_secs(),
                memory_mb: constants::DEFAULT_MEMORY_LIMIT / constants::MB,
                process_limit: constants::DEFAULT_PROCESS_LIMIT,
                fd_limit: constants::DEFAULT_FD_LIMIT,
                file_size_mb: constants::DEFAULT_FILE_SIZE_LIMIT / constants::MB,
                disk_quota_mb: constants::DEFAULT_TMPFS_SIZE_BYTES / constants::MB,
                network: false,
                packages: false,
                net_egress_mb: 0,
                net_ingress_mb: 0,
            },
            Self::Executor => ProfileLimits {
                wall_time_sec: constants::EXECUTOR_DEFAULT_WALL_TIME.as_secs(),
                cpu_time_sec: constants::EXECUTOR_DEFAULT_CPU_TIME.as_secs(),
                memory_mb: constants::EXECUTOR_DEFAULT_MEMORY / constants::MB,
                process_limit: constants::EXECUTOR_DEFAULT_PROCESSES,
                fd_limit: constants::EXECUTOR_DEFAULT_FD_LIMIT,
                file_size_mb: constants::EXECUTOR_DEFAULT_FILE_SIZE / constants::MB,
                disk_quota_mb: constants::EXECUTOR_DEFAULT_DISK_QUOTA / constants::MB,
                network: true,
                packages: true,
                net_egress_mb: constants::DEFAULT_NET_EGRESS / constants::MB,
                net_ingress_mb: constants::DEFAULT_NET_INGRESS / constants::MB,
            },
        }
    }

    pub fn hardcoded_max(&self) -> ProfileLimits {
        ProfileLimits {
            wall_time_sec: constants::MAX_ABSOLUTE_WALL_TIME.as_secs(),
            cpu_time_sec: constants::MAX_ABSOLUTE_CPU_TIME.as_secs(),
            memory_mb: constants::MAX_ABSOLUTE_MEMORY / constants::MB,
            process_limit: constants::MAX_ABSOLUTE_PROCESSES,
            fd_limit: constants::MAX_ABSOLUTE_FD_LIMIT,
            file_size_mb: constants::MAX_ABSOLUTE_MEMORY / constants::MB,
            disk_quota_mb: constants::MAX_ABSOLUTE_MEMORY / constants::MB,
            network: matches!(self, Self::Executor),
            packages: matches!(self, Self::Executor),
            net_egress_mb: constants::DEFAULT_NET_EGRESS / constants::MB,
            net_ingress_mb: constants::DEFAULT_NET_INGRESS / constants::MB,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedLimits {
    pub wall_time: Duration,
    pub cpu_time: Duration,
    pub memory_bytes: u64,
    pub process_limit: u32,
    pub fd_limit: u64,
    pub file_size_bytes: u64,
    pub disk_quota_bytes: u64,
    pub network: bool,
    pub packages: bool,
    pub net_egress_bytes: u64,
    pub net_ingress_bytes: u64,
    pub dns_servers: Vec<String>,
    pub was_capped: bool,
}

pub fn resolve_limits(
    profile: SecurityProfile,
    operator_config: Option<&ProfileConfig>,
    client_wall_time: Option<u64>,
    client_cpu_time: Option<u64>,
    client_memory_mb: Option<u64>,
    client_process_limit: Option<u32>,
    client_dns: Option<Vec<String>>,
) -> ResolvedLimits {
    let defaults = match operator_config {
        Some(cfg) => &cfg.defaults,
        None => &profile.hardcoded_defaults(),
    };
    let max = match operator_config {
        Some(cfg) => &cfg.max,
        None => &profile.hardcoded_max(),
    };
    let ceiling = profile.hardcoded_max();

    let mut was_capped = false;

    let resolve_u64 =
        |client: Option<u64>, default: u64, op_max: u64, abs_max: u64| -> (u64, bool) {
            let effective_max = op_max.min(abs_max);
            let requested = client.unwrap_or(default);
            if requested == 0 {
                return (default.min(effective_max), false);
            }
            if requested > effective_max {
                (effective_max, true)
            } else {
                (requested, false)
            }
        };

    let resolve_u32 =
        |client: Option<u32>, default: u32, op_max: u32, abs_max: u32| -> (u32, bool) {
            let effective_max = op_max.min(abs_max);
            let requested = client.unwrap_or(default);
            if requested == 0 {
                return (default.min(effective_max), false);
            }
            if requested > effective_max {
                (effective_max, true)
            } else {
                (requested, false)
            }
        };

    let (wall_sec, c1) = resolve_u64(
        client_wall_time,
        defaults.wall_time_sec,
        max.wall_time_sec,
        ceiling.wall_time_sec,
    );
    let (cpu_sec, c2) = resolve_u64(
        client_cpu_time,
        defaults.cpu_time_sec,
        max.cpu_time_sec,
        ceiling.cpu_time_sec,
    );
    let (mem_mb, c3) = resolve_u64(
        client_memory_mb,
        defaults.memory_mb,
        max.memory_mb,
        ceiling.memory_mb,
    );
    let (procs, c4) = resolve_u32(
        client_process_limit,
        defaults.process_limit,
        max.process_limit,
        ceiling.process_limit,
    );

    was_capped = c1 || c2 || c3 || c4;

    let dns_servers = client_dns.unwrap_or_else(|| {
        vec![
            constants::SANDBOX_DNS_PRIMARY.to_string(),
            constants::SANDBOX_DNS_SECONDARY.to_string(),
        ]
    });

    ResolvedLimits {
        wall_time: Duration::from_secs(wall_sec),
        cpu_time: Duration::from_secs(cpu_sec),
        memory_bytes: mem_mb * constants::MB,
        process_limit: procs,
        fd_limit: defaults.fd_limit.min(ceiling.fd_limit),
        file_size_bytes: defaults.file_size_mb * constants::MB,
        disk_quota_bytes: defaults.disk_quota_mb * constants::MB,
        network: defaults.network,
        packages: defaults.packages,
        net_egress_bytes: defaults.net_egress_mb * constants::MB,
        net_ingress_bytes: defaults.net_ingress_mb * constants::MB,
        dns_servers: dns_servers
            .into_iter()
            .take(constants::MAX_DNS_ENTRIES)
            .collect(),
        was_capped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judge_defaults_match_existing_constants() {
        let limits = SecurityProfile::Judge.hardcoded_defaults();
        assert_eq!(
            limits.wall_time_sec,
            constants::DEFAULT_WALL_TIME_LIMIT.as_secs()
        );
        assert_eq!(
            limits.memory_mb,
            constants::DEFAULT_MEMORY_LIMIT / constants::MB
        );
        assert!(!limits.network);
        assert!(!limits.packages);
    }

    #[test]
    fn executor_defaults_are_more_relaxed() {
        let judge = SecurityProfile::Judge.hardcoded_defaults();
        let executor = SecurityProfile::Executor.hardcoded_defaults();
        assert!(executor.wall_time_sec > judge.wall_time_sec);
        assert!(executor.memory_mb > judge.memory_mb);
        assert!(executor.process_limit > judge.process_limit);
        assert!(executor.network);
        assert!(executor.packages);
    }

    #[test]
    fn client_capped_to_operator_max() {
        let defaults = SecurityProfile::Executor.hardcoded_defaults();
        let max = ProfileLimits {
            wall_time_sec: 30,
            ..defaults.clone()
        };
        let config = ProfileConfig {
            defaults: defaults.clone(),
            max,
        };
        let resolved = resolve_limits(
            SecurityProfile::Executor,
            Some(&config),
            Some(120),
            None,
            None,
            None,
            None,
        );
        assert_eq!(resolved.wall_time, Duration::from_secs(30));
        assert!(resolved.was_capped);
    }

    #[test]
    fn client_under_cap_uses_requested() {
        let resolved = resolve_limits(
            SecurityProfile::Executor,
            None,
            Some(15),
            None,
            None,
            None,
            None,
        );
        assert_eq!(resolved.wall_time, Duration::from_secs(15));
        assert!(!resolved.was_capped);
    }

    #[test]
    fn zero_values_use_default() {
        let resolved = resolve_limits(
            SecurityProfile::Judge,
            None,
            Some(0),
            None,
            None,
            None,
            None,
        );
        assert_eq!(resolved.wall_time, constants::DEFAULT_WALL_TIME_LIMIT);
    }

    #[test]
    fn absolute_ceiling_overrides_operator_max() {
        let defaults = SecurityProfile::Executor.hardcoded_defaults();
        let max = ProfileLimits {
            wall_time_sec: 99999,
            ..defaults.clone()
        };
        let config = ProfileConfig {
            defaults: defaults.clone(),
            max,
        };
        let resolved = resolve_limits(
            SecurityProfile::Executor,
            Some(&config),
            Some(99999),
            None,
            None,
            None,
            None,
        );
        assert_eq!(resolved.wall_time, constants::MAX_ABSOLUTE_WALL_TIME);
        assert!(resolved.was_capped);
    }

    #[test]
    fn dns_capped_at_max_entries() {
        let resolved = resolve_limits(
            SecurityProfile::Executor,
            None,
            None,
            None,
            None,
            None,
            Some(vec![
                "1.1.1.1".into(),
                "8.8.8.8".into(),
                "9.9.9.9".into(),
                "208.67.222.222".into(),
                "208.67.220.220".into(),
            ]),
        );
        assert_eq!(resolved.dns_servers.len(), constants::MAX_DNS_ENTRIES);
    }

    #[test]
    fn judge_network_always_false() {
        let resolved = resolve_limits(SecurityProfile::Judge, None, None, None, None, None, None);
        assert!(!resolved.network);
    }

    #[test]
    fn no_config_uses_hardcoded_defaults() {
        let resolved = resolve_limits(SecurityProfile::Judge, None, None, None, None, None, None);
        assert_eq!(resolved.wall_time, constants::DEFAULT_WALL_TIME_LIMIT);
        assert_eq!(resolved.memory_bytes, constants::DEFAULT_MEMORY_LIMIT);
        assert_eq!(resolved.process_limit, constants::DEFAULT_PROCESS_LIMIT);
    }
}
