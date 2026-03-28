use super::constants;
use super::profile::ProfileConfig;
use super::types::{IsolateError, Result};
use std::net::Ipv4Addr;

pub fn validate_startup() -> Result<()> {
    validate_uid_base()?;
    Ok(())
}

fn validate_uid_base() -> Result<()> {
    let base: u32 = std::env::var("RUSTBOX_UID_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(constants::DEFAULT_UID_POOL_BASE);

    if base < constants::MIN_UID_BASE {
        return Err(IsolateError::Config(format!(
            "RUSTBOX_UID_BASE={} is below minimum {}",
            base,
            constants::MIN_UID_BASE
        )));
    }

    if base == constants::NOBODY_UID
        || (base..base + constants::DEFAULT_UID_POOL_SIZE).contains(&constants::NOBODY_UID)
    {
        return Err(IsolateError::Config(format!(
            "RUSTBOX_UID_BASE={} range overlaps with NOBODY_UID ({})",
            base,
            constants::NOBODY_UID
        )));
    }

    Ok(())
}

pub fn validate_profile_config(config: &ProfileConfig) -> Result<()> {
    if config.defaults.wall_time_sec > config.max.wall_time_sec {
        return Err(IsolateError::Config(format!(
            "profile default wall_time_sec ({}) > max ({})",
            config.defaults.wall_time_sec, config.max.wall_time_sec
        )));
    }
    if config.defaults.cpu_time_sec > config.max.cpu_time_sec {
        return Err(IsolateError::Config(format!(
            "profile default cpu_time_sec ({}) > max ({})",
            config.defaults.cpu_time_sec, config.max.cpu_time_sec
        )));
    }
    if config.defaults.memory_mb > config.max.memory_mb {
        return Err(IsolateError::Config(format!(
            "profile default memory_mb ({}) > max ({})",
            config.defaults.memory_mb, config.max.memory_mb
        )));
    }
    if config.defaults.process_limit > config.max.process_limit {
        return Err(IsolateError::Config(format!(
            "profile default process_limit ({}) > max ({})",
            config.defaults.process_limit, config.max.process_limit
        )));
    }
    Ok(())
}

pub fn validate_dns_servers(servers: &[String]) -> Result<Vec<String>> {
    let mut validated = Vec::new();
    for server in servers.iter().take(constants::MAX_DNS_ENTRIES) {
        if server.parse::<Ipv4Addr>().is_err() {
            return Err(IsolateError::Config(format!(
                "DNS server '{}' is not a valid IPv4 address",
                server
            )));
        }
        let is_blocked = constants::BLOCKED_NET_RANGES
            .iter()
            .any(|range| ip_in_cidr(server, range));
        if is_blocked {
            return Err(IsolateError::Config(format!(
                "DNS server '{}' is in a blocked network range",
                server
            )));
        }
        validated.push(server.clone());
    }
    Ok(validated)
}

fn ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    let ip: Ipv4Addr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let net: Ipv4Addr = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let prefix: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(net);
    (ip_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dns_accepted() {
        let result = validate_dns_servers(&["1.1.1.1".into(), "8.8.8.8".into()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn invalid_dns_rejected() {
        let result = validate_dns_servers(&["not-an-ip".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn blocked_dns_rejected() {
        let result = validate_dns_servers(&["169.254.169.254".into()]);
        assert!(result.is_err());

        let result = validate_dns_servers(&["10.0.0.1".into()]);
        assert!(result.is_err());

        let result = validate_dns_servers(&["127.0.0.1".into()]);
        assert!(result.is_err());

        let result = validate_dns_servers(&["192.168.1.1".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn public_dns_allowed() {
        let result = validate_dns_servers(&["1.1.1.1".into()]);
        assert!(result.is_ok());

        let result = validate_dns_servers(&["8.8.8.8".into()]);
        assert!(result.is_ok());

        let result = validate_dns_servers(&["9.9.9.9".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn dns_capped_at_max() {
        let servers: Vec<String> = (0..10).map(|i| format!("1.1.1.{}", i)).collect();
        let result = validate_dns_servers(&servers).unwrap();
        assert_eq!(result.len(), constants::MAX_DNS_ENTRIES);
    }

    #[test]
    fn ip_in_cidr_works() {
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.0/8"));
        assert!(ip_in_cidr("10.255.255.255", "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1", "10.0.0.0/8"));
        assert!(ip_in_cidr("192.168.1.1", "192.168.0.0/16"));
        assert!(!ip_in_cidr("192.169.1.1", "192.168.0.0/16"));
        assert!(ip_in_cidr("169.254.169.254", "169.254.0.0/16"));
        assert!(ip_in_cidr("172.16.0.1", "172.16.0.0/12"));
        assert!(ip_in_cidr("172.31.255.255", "172.16.0.0/12"));
        assert!(!ip_in_cidr("172.32.0.1", "172.16.0.0/12"));
    }

    #[test]
    fn profile_config_default_exceeds_max_rejected() {
        use crate::config::profile::{ProfileConfig, ProfileLimits, SecurityProfile};
        let defaults = SecurityProfile::Executor.hardcoded_defaults();
        let max = ProfileLimits {
            wall_time_sec: 10,
            ..defaults.clone()
        };
        let config = ProfileConfig {
            defaults: ProfileLimits {
                wall_time_sec: 60,
                ..defaults.clone()
            },
            max,
        };
        assert!(validate_profile_config(&config).is_err());
    }

    #[test]
    fn profile_config_valid_accepted() {
        use crate::config::profile::{ProfileConfig, SecurityProfile};
        let defaults = SecurityProfile::Executor.hardcoded_defaults();
        let max = SecurityProfile::Executor.hardcoded_max();
        let config = ProfileConfig { defaults, max };
        assert!(validate_profile_config(&config).is_ok());
    }
}
