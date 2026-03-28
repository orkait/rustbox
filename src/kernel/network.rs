use crate::config::constants;
use crate::config::types::{IsolateError, Result};
use std::process::Command;

fn run_cmd(program: &str, args: &[&str], context: &str) -> Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        IsolateError::Namespace(format!("{}: failed to run {}: {}", context, program, e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(IsolateError::Namespace(format!(
            "{}: {} {:?} failed: {}",
            context,
            program,
            args,
            stderr.trim()
        )));
    }
    Ok(())
}

fn run_cmd_ok_if_exists(program: &str, args: &[&str], context: &str) -> Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        IsolateError::Namespace(format!("{}: failed to run {}: {}", context, program, e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") || stderr.contains("already exists") {
            return Ok(());
        }
        return Err(IsolateError::Namespace(format!(
            "{}: {} {:?} failed: {}",
            context,
            program,
            args,
            stderr.trim()
        )));
    }
    Ok(())
}

pub fn check_bridge_prerequisites() -> Result<()> {
    Command::new("ip")
        .arg("link")
        .output()
        .map_err(|_| IsolateError::Namespace("'ip' command not found. Install iproute2.".into()))?;

    Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
        .map_err(|_| {
            IsolateError::Namespace("'nft' command not found. Install nftables.".into())
        })?;

    let modprobe_result = Command::new("modprobe").arg("br_netfilter").output();

    match modprobe_result {
        Ok(output) if output.status.success() => {}
        _ => {
            let path = std::path::Path::new("/proc/sys/net/bridge/bridge-nf-call-iptables");
            if !path.exists() {
                return Err(IsolateError::Namespace(
                    "br_netfilter module not available. Bridge filtering will not work.".into(),
                ));
            }
        }
    }

    run_cmd(
        "sysctl",
        &["-w", "net.bridge.bridge-nf-call-iptables=1"],
        "enable bridge netfilter",
    )?;
    run_cmd(
        "sysctl",
        &["-w", "net.bridge.bridge-nf-call-ip6tables=1"],
        "enable bridge netfilter ipv6",
    )?;
    run_cmd(
        "sysctl",
        &["-w", "net.ipv4.ip_forward=1"],
        "enable ip forwarding",
    )?;

    Ok(())
}

pub fn setup_bridge() -> Result<()> {
    check_bridge_prerequisites()?;

    run_cmd_ok_if_exists(
        "ip",
        &["link", "add", constants::BRIDGE_NAME, "type", "bridge"],
        "create bridge",
    )?;

    run_cmd_ok_if_exists(
        "ip",
        &[
            "addr",
            "add",
            constants::BRIDGE_GATEWAY_CIDR,
            "dev",
            constants::BRIDGE_NAME,
        ],
        "assign bridge IP",
    )?;

    run_cmd(
        "ip",
        &["link", "set", constants::BRIDGE_NAME, "up"],
        "bring bridge up",
    )?;

    setup_nftables()?;
    setup_nat()?;

    log::info!(
        "Bridge {} ready (gateway={}, subnet={})",
        constants::BRIDGE_NAME,
        constants::BRIDGE_GATEWAY,
        constants::BRIDGE_SUBNET
    );

    Ok(())
}

fn setup_nftables() -> Result<()> {
    let mut ruleset = String::new();
    ruleset.push_str("table inet rustbox {\n");

    ruleset.push_str("  set blocked_dst {\n");
    ruleset.push_str("    type ipv4_addr\n");
    ruleset.push_str("    flags interval\n");
    ruleset.push_str("    elements = { ");
    let elements: Vec<&str> = constants::BLOCKED_NET_RANGES.to_vec();
    ruleset.push_str(&elements.join(", "));
    ruleset.push_str(" }\n");
    ruleset.push_str("  }\n");

    ruleset.push_str("  chain forward {\n");
    ruleset.push_str("    type filter hook forward priority 0; policy accept;\n");

    ruleset.push_str(&format!(
        "    iifname \"{}\" ip daddr {} accept\n",
        constants::BRIDGE_NAME,
        constants::BRIDGE_GATEWAY
    ));

    ruleset.push_str(&format!(
        "    iifname \"{}\" ip daddr {} drop\n",
        constants::BRIDGE_NAME,
        constants::BRIDGE_SUBNET
    ));

    ruleset.push_str(&format!(
        "    iifname \"{}\" ip daddr @blocked_dst drop\n",
        constants::BRIDGE_NAME
    ));

    ruleset.push_str("  }\n");
    ruleset.push_str("}\n");

    let output = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(ruleset.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| IsolateError::Namespace(format!("nft ruleset load failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(IsolateError::Namespace(format!(
                "nft ruleset load failed: {}",
                stderr.trim()
            )));
        }
    }

    Ok(())
}

fn setup_nat() -> Result<()> {
    let nat_ruleset = format!(
        "table ip rustbox_nat {{\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority {}; policy accept;\n\
         \x20   ip saddr {} masquerade\n\
         \x20 }}\n\
         }}",
        constants::NFTABLES_NAT_PRIORITY,
        constants::BRIDGE_SUBNET
    );

    let output = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(nat_ruleset.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| IsolateError::Namespace(format!("nft NAT setup failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(IsolateError::Namespace(format!(
                "nft NAT setup failed: {}",
                stderr.trim()
            )));
        }
    }

    Ok(())
}

pub fn sandbox_ip_for_uid(uid: u32) -> (String, String) {
    let offset = uid - constants::DEFAULT_UID_POOL_BASE;
    let third = (offset / 64) + 1;
    let fourth = (offset % 64) * 4 + 2;
    let sandbox_ip = format!("10.200.{}.{}", third, fourth);
    let gateway_ip = constants::BRIDGE_GATEWAY.to_string();
    (sandbox_ip, gateway_ip)
}

pub fn veth_names_for_uid(uid: u32) -> (String, String) {
    (
        format!("{}{}", constants::VETH_HOST_PREFIX, uid),
        format!("{}{}", constants::VETH_SANDBOX_PREFIX, uid),
    )
}

pub fn create_sandbox_network(sandbox_pid: u32, uid: u32) -> Result<NetworkHandle> {
    let (veth_host, veth_sandbox) = veth_names_for_uid(uid);
    let (sandbox_ip, _gateway) = sandbox_ip_for_uid(uid);
    let sandbox_cidr = format!("{}/30", sandbox_ip);
    let pid_str = sandbox_pid.to_string();

    run_cmd(
        "ip",
        &[
            "link",
            "add",
            &veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &veth_sandbox,
        ],
        "create veth pair",
    )?;

    let cleanup_on_error = |e: IsolateError| -> IsolateError {
        let _ = Command::new("ip")
            .args(["link", "del", &veth_host])
            .output();
        e
    };

    run_cmd(
        "ip",
        &["link", "set", &veth_host, "master", constants::BRIDGE_NAME],
        "attach veth to bridge",
    )
    .map_err(cleanup_on_error)?;

    run_cmd(
        "ip",
        &["link", "set", &veth_sandbox, "netns", &pid_str],
        "move veth to sandbox namespace",
    )
    .map_err(|e| {
        let _ = Command::new("ip")
            .args(["link", "del", &veth_host])
            .output();
        e
    })?;

    run_cmd(
        "ip",
        &["link", "set", &veth_host, "up"],
        "bring host veth up",
    )
    .map_err(|e| {
        let _ = Command::new("ip")
            .args(["link", "del", &veth_host])
            .output();
        e
    })?;

    Ok(NetworkHandle {
        veth_host,
        uid,
        sandbox_ip,
        sandbox_cidr,
    })
}

pub fn configure_sandbox_side(
    veth_sandbox: &str,
    sandbox_cidr: &str,
    gateway: &str,
    dns_servers: &[String],
) -> Result<()> {
    run_cmd(
        "ip",
        &["addr", "add", sandbox_cidr, "dev", veth_sandbox],
        "assign sandbox IP",
    )?;

    run_cmd(
        "ip",
        &["link", "set", veth_sandbox, "up"],
        "bring sandbox veth up",
    )?;

    run_cmd(
        "ip",
        &["route", "add", "default", "via", gateway],
        "add default route",
    )?;

    Ok(())
}

pub fn cleanup_sandbox_network(uid: u32) {
    let (veth_host, _) = veth_names_for_uid(uid);
    let _ = Command::new("ip")
        .args(["link", "del", &veth_host])
        .output();
}

pub fn read_veth_bytes(uid: u32) -> (u64, u64) {
    let (veth_host, _) = veth_names_for_uid(uid);
    let tx = read_net_stat(&veth_host, "tx_bytes");
    let rx = read_net_stat(&veth_host, "rx_bytes");
    (tx, rx)
}

fn read_net_stat(iface: &str, stat: &str) -> u64 {
    let path = format!("/sys/class/net/{}/statistics/{}", iface, stat);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub struct NetworkHandle {
    pub veth_host: String,
    pub uid: u32,
    pub sandbox_ip: String,
    pub sandbox_cidr: String,
}

impl Drop for NetworkHandle {
    fn drop(&mut self) {
        cleanup_sandbox_network(self.uid);
    }
}

pub fn write_resolv_conf(chroot_path: &std::path::Path, dns_servers: &[String]) -> Result<()> {
    let etc_dir = chroot_path.join("etc");
    if !etc_dir.exists() {
        std::fs::create_dir_all(&etc_dir)
            .map_err(|e| IsolateError::Config(format!("create /etc in chroot: {}", e)))?;
    }

    let resolv_path = etc_dir.join("resolv.conf");
    let mut content = String::new();
    for server in dns_servers {
        content.push_str(&format!("nameserver {}\n", server));
    }
    std::fs::write(&resolv_path, &content)
        .map_err(|e| IsolateError::Config(format!("write resolv.conf: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_ip_for_uid_generates_unique_ips() {
        let (ip1, _) = sandbox_ip_for_uid(constants::DEFAULT_UID_POOL_BASE);
        let (ip2, _) = sandbox_ip_for_uid(constants::DEFAULT_UID_POOL_BASE + 1);
        let (ip3, _) = sandbox_ip_for_uid(constants::DEFAULT_UID_POOL_BASE + 63);
        let (ip4, _) = sandbox_ip_for_uid(constants::DEFAULT_UID_POOL_BASE + 64);

        assert_eq!(ip1, "10.200.1.2");
        assert_eq!(ip2, "10.200.1.6");
        assert_eq!(ip3, "10.200.1.254");
        assert_eq!(ip4, "10.200.2.2");
        assert_ne!(ip1, ip2);
        assert_ne!(ip3, ip4);
    }

    #[test]
    fn veth_names_use_uid() {
        let (host, sandbox) = veth_names_for_uid(60042);
        assert_eq!(host, format!("{}60042", constants::VETH_HOST_PREFIX));
        assert_eq!(sandbox, format!("{}60042", constants::VETH_SANDBOX_PREFIX));
    }

    #[test]
    fn sandbox_ips_dont_collide_across_pool() {
        let mut ips = std::collections::HashSet::new();
        for uid in constants::DEFAULT_UID_POOL_BASE
            ..constants::DEFAULT_UID_POOL_BASE + constants::DEFAULT_UID_POOL_SIZE
        {
            let (ip, _) = sandbox_ip_for_uid(uid);
            assert!(
                ips.insert(ip.clone()),
                "IP collision at uid {}: {}",
                uid,
                ip
            );
        }
    }
}
