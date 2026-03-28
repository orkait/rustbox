use std::time::Duration;

// --- Tier 1: Compile-time constants (structural, POSIX, kernel) ---

pub const NOBODY_UID: u32 = 65534;
pub const NOBODY_GID: u32 = 65534;

pub const EXIT_EXEC_FAILURE: i32 = 127;

pub const READ_BUFFER_SIZE: usize = 4096;

pub const CLONE_STACK_SIZE: usize = 2 * MB as usize;

pub const MAX_POOL_SIZE: u32 = 4096;

pub const MAX_CGROUP_INSTANCE_ID_LEN: usize = 255;

// --- Tier 1: Default resource limits (IsolateConfig fallbacks) ---

pub const DEFAULT_MEMORY_LIMIT: u64 = 128 * MB;
pub const DEFAULT_FILE_SIZE_LIMIT: u64 = 64 * MB;
pub const DEFAULT_STACK_LIMIT: u64 = 8 * MB;
pub const DEFAULT_FD_LIMIT: u64 = 64;
pub const DEFAULT_PROCESS_LIMIT: u32 = 10;
pub const DEFAULT_IO_BUFFER_SIZE: usize = 8192;

pub const DEFAULT_CPU_TIME_LIMIT: Duration = Duration::from_secs(10);
pub const DEFAULT_WALL_TIME_LIMIT: Duration = Duration::from_secs(20);

// --- Tier 1: Supervisor / process management constants ---

pub const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const SUPERVISOR_SETUP_BUDGET: Duration = Duration::from_secs(3);
pub const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

// --- Tier 1: Cgroup retry constants ---

pub const CGROUP_RETRY_COUNT: u32 = 20;
pub const CGROUP_RETRY_SLEEP: Duration = Duration::from_millis(25);
pub const CGROUP_SECOND_KILL_ATTEMPT: u32 = 5;

// --- Tier 1: Output collection defaults ---

pub const DEFAULT_PIPE_BUFFER_SIZE: u64 = MB;

pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * KB;

pub const MS_PER_SEC: u64 = 1000;
pub const MS_PER_SEC_F64: f64 = 1000.0;
pub const USEC_PER_MS: u64 = 1000;
pub const USEC_PER_SEC: f64 = 1_000_000.0;

pub const BITS_PER_WORD: usize = 64;

pub const INODE_SIZE_RATIO: u64 = 16_384;
pub const MIN_INODES: u64 = 4_096;
pub const MAX_INODES: u64 = 1_048_576;
pub const MIN_INODE_OVERRIDE: u64 = 1_024;

pub const SANDBOX_HOME: &str = "/tmp/sandbox";
pub const SANDBOX_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
pub const SANDBOX_LOCALE: &str = "C.UTF-8";
pub const SANDBOX_HOSTNAME: &str = "rustbox-sandbox";
pub const SANDBOX_TEXT_ENCODING: &str = "utf-8";
pub const DEFAULT_INSTANCE_ID: &str = "rustbox/0";

pub const DEFAULT_VIRTUAL_MEMORY_LIMIT: u64 = 1024 * MB;
pub const DEFAULT_TMPFS_SIZE_BYTES: u64 = 256 * MB;
pub const MIN_TMPFS_SIZE: u64 = 4 * MB;
pub const MIN_SHM_SIZE: u64 = MB;
pub const SHM_SIZE_DIVISOR: u64 = 16;
pub const SHM_INODE_LIMIT: u64 = 128;

pub const WORLD_WRITABLE_BIT: u32 = 0o002;
pub const PERMISSION_MASK: u32 = 0o777;

pub const PERM_DIR_STANDARD: u32 = 0o755;
pub const PERM_FILE_SOURCE: u32 = 0o644;
pub const PERM_FILE_PRIVATE: u32 = 0o600;
pub const PERM_DEVICE_NODE: u32 = 0o666;
pub const PERM_UMASK_RESTRICTIVE: u32 = 0o077;
pub const PERM_DIR_TEMP: u32 = 0o700;

pub const DEFAULT_OUTPUT_COMBINED_LIMIT: usize = 10 * MB as usize;
pub const DEFAULT_OUTPUT_STDOUT_LIMIT: usize = 8 * MB as usize;
pub const DEFAULT_OUTPUT_STDERR_LIMIT: usize = 2 * MB as usize;
pub const DEFAULT_OUTPUT_COLLECTION_TIMEOUT_MS: u64 = 5000;

// --- Tier 1: Validator warning thresholds ---

pub const VALIDATOR_MIN_MEMORY_WARN: u64 = MB;
pub const VALIDATOR_MAX_MEMORY_WARN: u64 = 8 * 1024 * MB;
pub const VALIDATOR_MAX_TIME_WARN_SECS: u64 = 600;
pub const VALIDATOR_MAX_PROCESS_WARN: u32 = 4096;

// --- Tier 2: Env-configurable defaults ---

pub const DEFAULT_UID_POOL_BASE: u32 = 60000;
pub const DEFAULT_UID_POOL_SIZE: u32 = 1000;
pub const DEFAULT_SIGTERM_GRACE: Duration = Duration::from_millis(200);
pub const DEFAULT_SUPERVISOR_WALL_FALLBACK: Duration = DEFAULT_WALL_TIME_LIMIT;

// --- Tier 1: Absolute ceilings (nobody can exceed, not even operator) ---

pub const MAX_ABSOLUTE_WALL_TIME: Duration = Duration::from_secs(600);
pub const MAX_ABSOLUTE_CPU_TIME: Duration = Duration::from_secs(300);
pub const MAX_ABSOLUTE_MEMORY: u64 = 8 * 1024 * MB;
pub const MAX_ABSOLUTE_PROCESSES: u32 = 1024;
pub const MAX_ABSOLUTE_FD_LIMIT: u64 = 4096;
pub const MAX_DNS_ENTRIES: usize = 3;
pub const MIN_UID_BASE: u32 = 1000;

// --- Tier 1: Executor profile defaults ---

pub const EXECUTOR_DEFAULT_WALL_TIME: Duration = Duration::from_secs(60);
pub const EXECUTOR_DEFAULT_CPU_TIME: Duration = Duration::from_secs(30);
pub const EXECUTOR_DEFAULT_MEMORY: u64 = 2048 * MB;
pub const EXECUTOR_DEFAULT_PROCESSES: u32 = 64;
pub const EXECUTOR_DEFAULT_FD_LIMIT: u64 = 256;
pub const EXECUTOR_DEFAULT_FILE_SIZE: u64 = 64 * MB;
pub const EXECUTOR_DEFAULT_DISK_QUOTA: u64 = 1024 * MB;

// --- Tier 1: Network defaults (executor only) ---

pub const DEFAULT_NET_EGRESS: u64 = 100 * MB;
pub const DEFAULT_NET_INGRESS: u64 = 100 * MB;
pub const SANDBOX_DNS_PRIMARY: &str = "1.1.1.1";
pub const SANDBOX_DNS_SECONDARY: &str = "8.8.8.8";
pub const BRIDGE_NAME: &str = "br-rustbox";
pub const BRIDGE_SUBNET: &str = "10.200.0.0/16";
pub const BRIDGE_GATEWAY: &str = "10.200.0.1";
pub const BRIDGE_GATEWAY_CIDR: &str = "10.200.0.1/16";
pub const VETH_HOST_PREFIX: &str = "veth-rb-";
pub const VETH_SANDBOX_PREFIX: &str = "veth-sb-";
pub const NET_QUOTA_POLL_INTERVAL: Duration = Duration::from_millis(100);

// --- Tier 1: Blocked network ranges ---

pub const BLOCKED_NET_RANGES: &[&str] = &[
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
];

// --- Tier 1: Benchmark thresholds ---

pub const BENCH_COLD_P50_MS: u64 = 100;
pub const BENCH_COLD_P95_MS: u64 = 200;
pub const BENCH_WARM_P50_MS: u64 = 150;
pub const BENCH_WARM_P95_MS: u64 = 300;
pub const BENCH_FULL_P50_MS: u64 = 250;
pub const BENCH_FULL_P95_MS: u64 = 500;

pub const TEST_SHORT_CPU_LIMIT: Duration = Duration::from_secs(1);
pub const TEST_SHORT_WALL_LIMIT: Duration = Duration::from_secs(3);
pub const TEST_SHORT_CPU_SECS: u64 = 1;
pub const TEST_SHORT_WALL_SECS: u64 = 3;

// Syscall numbers not yet in the libc crate (kernel 5.10+)
pub const SYS_PROCESS_MADVISE: i64 = 440;
pub const SYS_PROCESS_MRELEASE: i64 = 448;
pub const SYS_SET_MEMPOLICY_HOME_NODE: i64 = 450;
pub const SYS_MAP_SHADOW_STACK: i64 = 453;
pub const SYS_STATMOUNT: i64 = 457;
pub const SYS_LISTMOUNT: i64 = 458;
pub const SYS_LSM_SET_SELF_ATTR: i64 = 460;

pub struct RuntimeTuning {
    pub sigterm_grace: Duration,
    pub cgroup_retry_count: u32,
    pub cgroup_retry_sleep: Duration,
}

fn read_env_u64(var: &str, default: u64) -> u64 {
    match std::env::var(var) {
        Ok(ref v) => match v.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                log::warn!(
                    "{}='{}' is not a valid integer, using default {}",
                    var,
                    v,
                    default
                );
                default
            }
        },
        Err(_) => default,
    }
}

impl RuntimeTuning {
    fn load() -> Self {
        Self {
            sigterm_grace: Duration::from_millis(read_env_u64(
                "RUSTBOX_SIGTERM_GRACE_MS",
                DEFAULT_SIGTERM_GRACE.as_millis() as u64,
            )),
            cgroup_retry_count: read_env_u64(
                "RUSTBOX_CGROUP_RETRY_COUNT",
                CGROUP_RETRY_COUNT as u64,
            ) as u32,
            cgroup_retry_sleep: Duration::from_millis(read_env_u64(
                "RUSTBOX_CGROUP_RETRY_SLEEP_MS",
                CGROUP_RETRY_SLEEP.as_millis() as u64,
            )),
        }
    }
}

pub fn runtime_tuning() -> &'static RuntimeTuning {
    use std::sync::OnceLock;
    static TUNING: OnceLock<RuntimeTuning> = OnceLock::new();
    TUNING.get_or_init(RuntimeTuning::load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_baseline() {
        assert_eq!(NOBODY_UID, 65534_u32);
        assert_eq!(NOBODY_GID, 65534_u32);
        assert_eq!(DEFAULT_MEMORY_LIMIT, 128 * MB);
        assert_eq!(DEFAULT_FILE_SIZE_LIMIT, 64 * MB);
        assert_eq!(DEFAULT_STACK_LIMIT, 8 * MB);
        assert_eq!(DEFAULT_FD_LIMIT, 64);
        assert_eq!(DEFAULT_PROCESS_LIMIT, 10);
        assert_eq!(DEFAULT_IO_BUFFER_SIZE, 8192);
        assert_eq!(DEFAULT_CPU_TIME_LIMIT, Duration::from_secs(10));
        assert_eq!(DEFAULT_WALL_TIME_LIMIT, Duration::from_secs(20));
        assert_eq!(CLONE_STACK_SIZE, 2 * MB as usize);
        assert_eq!(MAX_POOL_SIZE, 4096);
        assert_eq!(MAX_CGROUP_INSTANCE_ID_LEN, 255);
        assert_eq!(CGROUP_RETRY_COUNT, 20);
        assert_eq!(CGROUP_RETRY_SLEEP, Duration::from_millis(25));
        assert_eq!(DEFAULT_OUTPUT_COMBINED_LIMIT, 10 * MB as usize);
        assert_eq!(DEFAULT_OUTPUT_STDOUT_LIMIT, 8 * MB as usize);
        assert_eq!(DEFAULT_OUTPUT_STDERR_LIMIT, 2 * MB as usize);
        assert_eq!(DEFAULT_OUTPUT_COLLECTION_TIMEOUT_MS, 5000);
        assert_eq!(VALIDATOR_MIN_MEMORY_WARN, MB);
        assert_eq!(VALIDATOR_MAX_MEMORY_WARN, 8 * 1024 * MB);
        assert_eq!(VALIDATOR_MAX_TIME_WARN_SECS, 600);
        assert_eq!(VALIDATOR_MAX_PROCESS_WARN, 4096);
        assert_eq!(DEFAULT_UID_POOL_BASE, 60000_u32);
        assert_eq!(DEFAULT_UID_POOL_SIZE, 1000);
        assert_eq!(DEFAULT_SIGTERM_GRACE, Duration::from_millis(200));
        assert_eq!(
            DEFAULT_SUPERVISOR_WALL_FALLBACK, DEFAULT_WALL_TIME_LIMIT,
            "supervisor wall fallback must derive from the same default"
        );
        assert_eq!(EXIT_EXEC_FAILURE, 127);
        assert_eq!(READ_BUFFER_SIZE, 4096);
        assert_eq!(DEFAULT_PIPE_BUFFER_SIZE, MB);
    }
}
