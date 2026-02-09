/// Enhanced lock manager implementing file-based locking
/// Simplified version without heartbeat thread (R4: heartbeat thread removed)
use crate::config::types::{HealthStatus, LockError, LockInfo, LockManagerHealth, LockMetrics, LockResult};
use log::{info, warn};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

/// Global lock manager instance
static GLOBAL_LOCK_MANAGER: OnceLock<Arc<Mutex<RustboxLockManager>>> = OnceLock::new();

/// flock operation constants
const LOCK_EX: i32 = 2; // Exclusive lock
const LOCK_NB: i32 = 4; // Non-blocking

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

/// Resource limits for lock manager
const MAX_CONCURRENT_LOCKS: u64 = 1000;

/// The main lock manager (simplified - no heartbeat thread)
pub struct RustboxLockManager {
    lock_dir: PathBuf,
    stale_timeout: Duration,
    cleanup_thread: Option<JoinHandle<()>>,
    metrics: Arc<Mutex<LockManagerMetrics>>,
    active_locks: Arc<AtomicU64>,
}

/// Internal metrics tracking
#[derive(Debug, Default)]
struct LockManagerMetrics {
    total_acquisitions: AtomicU64,
    total_contentions: AtomicU64,
    total_cleanups: AtomicU64,
    acquisition_times: Vec<Duration>,
    errors_by_type: HashMap<String, u64>,
    stale_locks_cleaned: AtomicU64,
}

/// Individual box lock (simplified - no heartbeat thread)
#[derive(Debug)]
#[allow(dead_code)]
pub struct BoxLock {
    box_id: u32,
    lock_file: File,
    lock_path: PathBuf,
    owner_pid: u32,
    created_at: SystemTime,
}

/// RAII guard for box locks
#[derive(Debug)]
pub struct BoxLockGuard {
    lock: Option<Arc<Mutex<BoxLock>>>,
    _cleanup: DropGuard,
}

/// Drop guard for cleanup
#[derive(Debug)]
struct DropGuard {
    box_id: u32,
    lock_dir: PathBuf,
    active_locks_counter: Arc<AtomicU64>,
}

impl RustboxLockManager {
    /// Determine the best lock directory to use with fallback options
    fn get_lock_directory() -> LockResult<PathBuf> {
        // Preferred directories in order of preference
        let preferred_dirs = [
            "/var/run/rustbox/locks",
            "/tmp/rustbox/locks",
            "/tmp/.rustbox-locks",
        ];

        for dir_path in &preferred_dirs {
            let path = PathBuf::from(dir_path);

            // Try to create the parent directory first
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        continue; // Try next directory
                    }
                }
            }

            // Test if we can create the directory and write to it
            match std::fs::create_dir_all(&path) {
                Ok(()) => {
                    // Test write access
                    let test_file = path.join(format!(".access_test_{}", std::process::id()));
                    if std::fs::write(&test_file, b"test").is_ok() {
                        let _ = std::fs::remove_file(&test_file);
                        return Ok(path);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Directory exists, test write access
                    let test_file = path.join(format!(".access_test_{}", std::process::id()));
                    if std::fs::write(&test_file, b"test").is_ok() {
                        let _ = std::fs::remove_file(&test_file);
                        return Ok(path);
                    }
                }
                _ => continue, // Try next directory
            }
        }

        Err(LockError::PermissionDenied {
            details: "Cannot find or create a writable lock directory".to_string(),
        })
    }

    /// Create lock directory with robust concurrent handling
    fn create_lock_directory_with_retry(lock_dir: &Path) -> LockResult<()> {
        for attempt in 0..3 {
            match std::fs::create_dir_all(lock_dir) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Directory already exists, verify it's actually a directory
                    if lock_dir.is_dir() {
                        return Ok(());
                    } else {
                        return Err(LockError::PermissionDenied {
                            details: format!(
                                "Lock path {} exists but is not a directory",
                                lock_dir.display()
                            ),
                        });
                    }
                }
                Err(e) if attempt < 2 => {
                    // Retry after a short delay for transient errors
                    warn!(
                        "Failed to create lock directory on attempt {}: {}. Retrying...",
                        attempt + 1,
                        e
                    );
                    thread::sleep(Duration::from_millis(10 + attempt as u64 * 10));
                    continue;
                }
                Err(e) => {
                    return Err(LockError::PermissionDenied {
                        details: format!(
                            "Cannot create lock directory {} after {} attempts: {}",
                            lock_dir.display(),
                            attempt + 1,
                            e
                        ),
                    });
                }
            }
        }
        unreachable!()
    }

    /// Create new lock manager with enhanced safety
    pub fn new() -> LockResult<Self> {
        let lock_dir = Self::get_lock_directory()?;

        // Create lock directory with retry logic to handle concurrent creation
        Self::create_lock_directory_with_retry(&lock_dir)?;

        // Test write permissions with unique filename to avoid conflicts
        let test_file = lock_dir.join(format!(".write_test_{}", std::process::id()));
        std::fs::write(&test_file, b"test").map_err(|e| LockError::PermissionDenied {
            details: format!("Lock directory not writable: {}", e),
        })?;
        let _ = std::fs::remove_file(&test_file); // Don't fail if cleanup fails

        let manager = Self {
            lock_dir,
            stale_timeout: Duration::from_secs(10),
            cleanup_thread: None,
            metrics: Arc::new(Mutex::new(LockManagerMetrics::default())),
            active_locks: Arc::new(AtomicU64::new(0)),
        };

        info!(
            "Initialized RustboxLockManager at {}",
            manager.lock_dir.display()
        );
        Ok(manager)
    }

    /// Start background cleanup thread
    pub fn start_cleanup_thread(&mut self) -> LockResult<()> {
        let lock_dir = self.lock_dir.clone();
        let stale_timeout = self.stale_timeout;
        let metrics = Arc::clone(&self.metrics);

        let cleanup_thread = thread::spawn(move || {
            info!("Started lock cleanup thread");
            let cleanup_interval = Duration::from_secs(30);

            loop {
                // Perform cleanup
                if let Err(e) = Self::cleanup_stale_locks_worker(&lock_dir, stale_timeout, &metrics)
                {
                    warn!("Cleanup failed: {}", e);
                }

                // Wait for next cleanup cycle
                thread::sleep(cleanup_interval);
            }
        });

        self.cleanup_thread = Some(cleanup_thread);
        Ok(())
    }

    /// Core lock acquisition with retry logic and exponential backoff
    pub fn acquire_lock(&self, box_id: u32, timeout: Duration) -> LockResult<BoxLockGuard> {
        // Check resource limits before acquiring lock
        let current_locks = self.active_locks.load(Ordering::Acquire);
        if current_locks >= MAX_CONCURRENT_LOCKS {
            return Err(LockError::SystemError {
                message: format!(
                    "Too many concurrent locks: {}/{}",
                    current_locks, MAX_CONCURRENT_LOCKS
                ),
            });
        }

        let start_time = Instant::now();
        let lock_path = self.lock_dir.join(format!("box-{}.lock", box_id));
        let heartbeat_path = self.lock_dir.join(format!("box-{}.heartbeat", box_id));

        info!(
            "Attempting to acquire lock for box {} (active locks: {})",
            box_id, current_locks
        );

        // Step 1: Clean any stale lock first
        if let Err(e) = self.cleanup_stale_lock_if_needed(box_id) {
            warn!("Failed to cleanup stale lock for box {}: {}", box_id, e);
        }

        // Step 2: Retry loop with exponential backoff
        let mut retry_delay = Duration::from_millis(10);
        loop {
            match self.try_acquire_immediate(box_id, &lock_path, &heartbeat_path) {
                Ok(lock_guard) => {
                    let elapsed = start_time.elapsed();
                    info!("Acquired lock for box {} in {:?}", box_id, elapsed);

                    // Update metrics
                    self.record_acquisition(elapsed);
                    return Ok(lock_guard);
                }
                Err(LockError::Busy { .. }) => {
                    if start_time.elapsed() >= timeout {
                        self.record_timeout();
                        return Err(LockError::Timeout {
                            box_id,
                            waited: start_time.elapsed(),
                            current_owner: self.get_lock_owner(box_id),
                        });
                    }

                    // Exponential backoff with jitter
                    let jitter =
                        Duration::from_millis(fastrand::u64(0..=retry_delay.as_millis() as u64));
                    thread::sleep(retry_delay + jitter);
                    retry_delay = std::cmp::min(retry_delay * 2, Duration::from_millis(500));

                    self.record_contention();
                }
                Err(e) => {
                    self.record_error(&e);
                    return Err(e);
                }
            }
        }
    }

    /// Atomic lock acquisition attempt (simplified - no heartbeat)
    fn try_acquire_immediate(
        &self,
        box_id: u32,
        lock_path: &Path,
        _heartbeat_path: &Path,
    ) -> LockResult<BoxLockGuard> {
        // Step 1: Open lock file without truncating — never destroy data before holding flock
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;

        // Step 2: Try to acquire exclusive lock (non-blocking)
        #[cfg(unix)]
        let flock_result = unsafe { 
            use std::os::unix::io::AsRawFd;
            flock(lock_file.as_raw_fd(), LOCK_EX | LOCK_NB) 
        };
        
        #[cfg(not(unix))]
        let flock_result = {
            // Windows doesn't support flock, return error
            return Err(LockError::SystemError {
                message: "flock not supported on this platform".to_string(),
            });
        };
        
        if flock_result != 0 {
            let errno = std::io::Error::last_os_error();
            return match errno.raw_os_error() {
                Some(libc::EWOULDBLOCK) => Err(LockError::Busy {
                    box_id,
                    owner_pid: None,
                }),
                _ => Err(LockError::SystemError {
                    message: format!("flock failed: {}", errno),
                }),
            };
        }

        // Step 3: Now that we hold the lock, write our lock info
        let lock_info = LockInfo {
            pid: std::process::id(),
            box_id,
            created_at: SystemTime::now(),
            rustbox_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let lock_json = serde_json::to_string(&lock_info).map_err(|e| LockError::SystemError {
            message: e.to_string(),
        })?;

        let mut lock_file_mut = lock_file;
        lock_file_mut.seek(SeekFrom::Start(0))?;
        writeln!(lock_file_mut, "{}", lock_json)?;
        // Trim any stale trailing bytes from a previous (longer) lock info
        let pos = lock_file_mut.stream_position()?;
        lock_file_mut.set_len(pos)?;
        lock_file_mut.sync_all()?;

        // Step 4: Create the lock object (no heartbeat)
        let lock = BoxLock {
            box_id,
            lock_file: lock_file_mut,
            lock_path: lock_path.to_owned(),
            owner_pid: std::process::id(),
            created_at: SystemTime::now(),
        };

        // Step 5: Increment active lock counter
        self.active_locks.fetch_add(1, Ordering::Release);

        // Step 6: Return RAII guard
        Ok(BoxLockGuard {
            lock: Some(Arc::new(Mutex::new(lock))),
            _cleanup: DropGuard {
                box_id,
                lock_dir: self.lock_dir.clone(),
                active_locks_counter: self.active_locks.clone(),
            },
        })
    }

    /// Clean up stale lock if needed (simplified - no heartbeat check)
    fn cleanup_stale_lock_if_needed(&self, box_id: u32) -> LockResult<()> {
        let lock_path = self.lock_dir.join(format!("box-{}.lock", box_id));

        // If no lock file exists, nothing to clean
        if !lock_path.exists() {
            return Ok(());
        }

        // Try to read lock info — empty file means lock was released (truncated to zero)
        let lock_content = std::fs::read_to_string(&lock_path)?;
        if lock_content.trim().is_empty() {
            return Ok(()); // Lock file was truncated to zero — already released
        }
        let lock_info: LockInfo = serde_json::from_str(lock_content.lines().next().unwrap_or(""))
            .map_err(|_| LockError::CorruptedLock {
            box_id,
            details: "Invalid lock file format".to_string(),
        })?;

        // Check if the owning process is still alive
        if self.is_process_alive(lock_info.pid) {
            // Process exists and lock is active
            return Err(LockError::Busy {
                box_id,
                owner_pid: Some(lock_info.pid),
            });
        }

        // Lock is stale - clean it up
        warn!(
            "Cleaning up stale lock for box {} (pid {} not responding)",
            box_id, lock_info.pid
        );
        self.force_cleanup_box_resources(box_id)?;

        // Truncate lock file to zero (don't remove — prevents inode-reuse races)
        if let Ok(f) = OpenOptions::new().write(true).open(&lock_path) {
            let _ = f.set_len(0);
        }

        self.record_cleanup();
        Ok(())
    }

    /// Check if process is alive
    fn is_process_alive(&self, pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    /// Force cleanup box resources
    fn force_cleanup_box_resources(&self, box_id: u32) -> LockResult<()> {
        warn!("Force cleaning up resources for box {}", box_id);
        // In a real implementation, this would cleanup:
        // - Kill processes in the box
        // - Unmount filesystems
        // - Remove cgroups
        // - Clean up network namespaces
        // For now, we'll just log it
        Ok(())
    }

    /// Get current lock owner info
    fn get_lock_owner(&self, box_id: u32) -> Option<String> {
        let lock_path = self.lock_dir.join(format!("box-{}.lock", box_id));
        if let Ok(content) = std::fs::read_to_string(&lock_path) {
            if let Ok(lock_info) =
                serde_json::from_str::<LockInfo>(content.lines().next().unwrap_or(""))
            {
                return Some(format!("PID {}", lock_info.pid));
            }
        }
        None
    }

    /// Background cleanup worker
    fn cleanup_stale_locks_worker(
        lock_dir: &Path,
        stale_timeout: Duration,
        metrics: &Arc<Mutex<LockManagerMetrics>>,
    ) -> LockResult<()> {
        if !lock_dir.exists() {
            return Ok(());
        }

        let mut cleaned_count = 0;
        for entry in std::fs::read_dir(lock_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("lock") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(box_id_str) = stem.strip_prefix("box-") {
                        if let Ok(box_id) = box_id_str.parse::<u32>() {
                            // Check if this lock is stale
                            if Self::is_lock_stale(&path, stale_timeout).unwrap_or(false) {
                                warn!("Background cleanup: truncating stale lock for box {}", box_id);
                                // Truncate to zero instead of removing — prevents inode-reuse races
                                if let Ok(f) = OpenOptions::new().write(true).open(&path) {
                                    let _ = f.set_len(0);
                                }
                                let heartbeat_path =
                                    lock_dir.join(format!("box-{}.heartbeat", box_id));
                                let _ = std::fs::remove_file(heartbeat_path);
                                cleaned_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if cleaned_count > 0 {
            if let Ok(metrics) = metrics.lock() {
                metrics
                    .stale_locks_cleaned
                    .fetch_add(cleaned_count, Ordering::Relaxed);
            }
            info!("Background cleanup: removed {} stale locks", cleaned_count);
        }

        Ok(())
    }

    /// Check if a lock is stale
    fn is_lock_stale(lock_path: &Path, stale_timeout: Duration) -> LockResult<bool> {
        let content = std::fs::read_to_string(lock_path)?;
        if content.trim().is_empty() {
            return Ok(false); // Truncated to zero — already released, not stale
        }
        let lock_info: LockInfo = serde_json::from_str(content.lines().next().unwrap_or(""))
            .map_err(|e| LockError::SystemError {
                message: e.to_string(),
            })?;

        // Check if process is alive
        if std::path::Path::new(&format!("/proc/{}", lock_info.pid)).exists() {
            return Ok(false);
        }

        // Process is dead, check how long ago
        let age = SystemTime::now()
            .duration_since(lock_info.created_at)
            .unwrap_or(Duration::from_secs(0));

        Ok(age > stale_timeout)
    }

    /// Health check implementation
    pub fn health_check(&self) -> LockManagerHealth {
        let metrics = self.get_metrics();
        let active_locks = self.count_active_locks();
        let lock_directory_writable = self.test_directory_writable();
        let cleanup_thread_alive = self
            .cleanup_thread
            .as_ref()
            .is_some_and(|t| !t.is_finished());

        let status = if !lock_directory_writable {
            HealthStatus::Unhealthy
        } else if !cleanup_thread_alive || metrics.errors_by_type.values().sum::<u64>() > 10 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        LockManagerHealth {
            status,
            active_locks,
            stale_locks_cleaned: metrics.stale_locks_cleaned,
            lock_directory_writable,
            cleanup_thread_alive,
            metrics: LockMetrics {
                total_acquisitions: metrics.total_acquisitions,
                average_acquisition_time_ms: metrics.average_acquisition_time_ms,
                lock_contentions: metrics.lock_contentions,
                cleanup_operations: metrics.cleanup_operations,
                stale_locks_cleaned: metrics.stale_locks_cleaned,
                errors_by_type: metrics.errors_by_type,
            },
        }
    }

    /// Export Prometheus-style metrics
    pub fn export_metrics(&self) -> String {
        let metrics = self.get_metrics();
        format!(
            "# HELP rustbox_lock_acquisitions_total Total lock acquisitions\n\
             # TYPE rustbox_lock_acquisitions_total counter\n\
             rustbox_lock_acquisitions_total {}\n\
             \n\
             # HELP rustbox_lock_contentions_total Total lock contentions\n\
             # TYPE rustbox_lock_contentions_total counter\n\
             rustbox_lock_contentions_total {}\n\
             \n\
             # HELP rustbox_lock_cleanup_operations_total Total cleanup operations\n\
             # TYPE rustbox_lock_cleanup_operations_total counter\n\
             rustbox_lock_cleanup_operations_total {}\n\
             \n\
             # HELP rustbox_lock_acquisition_duration_ms Average lock acquisition time\n\
             # TYPE rustbox_lock_acquisition_duration_ms gauge\n\
             rustbox_lock_acquisition_duration_ms {}\n",
            metrics.total_acquisitions,
            metrics.lock_contentions,
            metrics.cleanup_operations,
            metrics.average_acquisition_time_ms
        )
    }

    // Metrics helpers
    fn record_acquisition(&self, elapsed: Duration) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.total_acquisitions.fetch_add(1, Ordering::Relaxed);
            metrics.acquisition_times.push(elapsed);

            // Keep only recent acquisition times (last 1000)
            if metrics.acquisition_times.len() > 1000 {
                metrics.acquisition_times.drain(0..500);
            }
        }
    }

    fn record_contention(&self) {
        if let Ok(metrics) = self.metrics.lock() {
            metrics.total_contentions.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_timeout(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            *metrics
                .errors_by_type
                .entry("timeout".to_string())
                .or_insert(0) += 1;
        }
    }

    fn record_cleanup(&self) {
        if let Ok(metrics) = self.metrics.lock() {
            metrics.total_cleanups.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_error(&self, error: &LockError) {
        if let Ok(mut metrics) = self.metrics.lock() {
            let error_type = match error {
                LockError::Busy { .. } => "busy",
                LockError::Timeout { .. } => "timeout",
                LockError::PermissionDenied { .. } => "permission_denied",
                LockError::FilesystemError { .. } => "filesystem_error",
                LockError::CorruptedLock { .. } => "corrupted_lock",
                LockError::SystemError { .. } => "system_error",
                LockError::NotInitialized => "not_initialized",
            };
            *metrics
                .errors_by_type
                .entry(error_type.to_string())
                .or_insert(0) += 1;
        }
    }

    fn get_metrics(&self) -> LockMetrics {
        if let Ok(metrics) = self.metrics.lock() {
            let avg_time = if metrics.acquisition_times.is_empty() {
                0.0
            } else {
                let total: Duration = metrics.acquisition_times.iter().sum();
                total.as_millis() as f64 / metrics.acquisition_times.len() as f64
            };

            LockMetrics {
                total_acquisitions: metrics.total_acquisitions.load(Ordering::Relaxed),
                average_acquisition_time_ms: avg_time,
                lock_contentions: metrics.total_contentions.load(Ordering::Relaxed),
                cleanup_operations: metrics.total_cleanups.load(Ordering::Relaxed),
                stale_locks_cleaned: metrics.stale_locks_cleaned.load(Ordering::Relaxed),
                errors_by_type: metrics.errors_by_type.clone(),
            }
        } else {
            LockMetrics {
                total_acquisitions: 0,
                average_acquisition_time_ms: 0.0,
                lock_contentions: 0,
                cleanup_operations: 0,
                stale_locks_cleaned: 0,
                errors_by_type: HashMap::new(),
            }
        }
    }

    fn count_active_locks(&self) -> u32 {
        if !self.lock_dir.exists() {
            return 0;
        }

        std::fs::read_dir(&self.lock_dir)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        entry.path().extension().and_then(|s| s.to_str()) == Some("lock")
                    })
                    .count() as u32
            })
            .unwrap_or(0)
    }

    fn test_directory_writable(&self) -> bool {
        let test_file = self
            .lock_dir
            .join(format!(".health_check_{}", std::process::id()));
        if std::fs::write(&test_file, b"test").is_ok() {
            let _ = std::fs::remove_file(&test_file); // Don't fail if cleanup fails
            true
        } else {
            false
        }
    }
}

impl Drop for RustboxLockManager {
    fn drop(&mut self) {
        // Cleanup thread will be terminated when process exits
        info!("RustboxLockManager shutdown complete");
    }
}

impl BoxLockGuard {
    /// Get the box ID for this lock
    pub fn box_id(&self) -> u32 {
        if let Some(lock) = &self.lock {
            if let Ok(lock) = lock.lock() {
                return lock.box_id;
            }
        }
        0
    }
}

impl Drop for BoxLockGuard {
    fn drop(&mut self) {
        // Lock is automatically released when lock_file goes out of scope (flock released on close)
        // No heartbeat thread to clean up
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        let lock_path = self.lock_dir.join(format!("box-{}.lock", self.box_id));

        // Truncate lock file to zero instead of removing — prevents inode-reuse races.
        // Another process may hold an flock on the same inode; removing the file and
        // re-creating it would give a new inode, allowing two processes to both think
        // they hold the lock.
        if let Ok(f) = OpenOptions::new().write(true).open(&lock_path) {
            let _ = f.set_len(0);
        }

        // Decrement the active lock counter
        let prev_count = self.active_locks_counter.fetch_sub(1, Ordering::Release);
        info!(
            "Lock released for box {} (active locks: {} -> {})",
            self.box_id,
            prev_count,
            prev_count - 1
        );
    }
}

// ============================================================================
// PUBLIC API - Simple interface for the rest of the codebase
// ============================================================================

/// Initialize the global lock manager
pub fn init_lock_manager() -> LockResult<()> {
    let mut manager = RustboxLockManager::new()?;
    manager.start_cleanup_thread()?;

    GLOBAL_LOCK_MANAGER
        .set(Arc::new(Mutex::new(manager)))
        .map_err(|_| LockError::SystemError {
            message: "Lock manager already initialized".to_string(),
        })?;

    info!("Global lock manager initialized successfully");
    Ok(())
}

/// Acquire a box lock with default 30 second timeout
pub fn acquire_box_lock(box_id: u32) -> LockResult<BoxLockGuard> {
    acquire_box_lock_with_timeout(box_id, Duration::from_secs(30))
}

/// Acquire a box lock with custom timeout
pub fn acquire_box_lock_with_timeout(box_id: u32, timeout: Duration) -> LockResult<BoxLockGuard> {
    let manager = GLOBAL_LOCK_MANAGER.get().ok_or(LockError::NotInitialized)?;

    let manager = manager.lock().map_err(|_| LockError::SystemError {
        message: "Failed to acquire lock manager mutex".to_string(),
    })?;

    manager.acquire_lock(box_id, timeout)
}

/// Get lock manager health status
pub fn get_lock_health() -> LockResult<LockManagerHealth> {
    let manager = GLOBAL_LOCK_MANAGER.get().ok_or(LockError::NotInitialized)?;

    let manager = manager.lock().map_err(|_| LockError::SystemError {
        message: "Failed to acquire lock manager mutex".to_string(),
    })?;

    Ok(manager.health_check())
}

/// Export metrics in Prometheus format
pub fn get_lock_metrics() -> LockResult<String> {
    let manager = GLOBAL_LOCK_MANAGER.get().ok_or(LockError::NotInitialized)?;

    let manager = manager.lock().map_err(|_| LockError::SystemError {
        message: "Failed to acquire lock manager mutex".to_string(),
    })?;

    Ok(manager.export_metrics())
}

/// Utility function for file locking (for instances.json etc)
///
/// Uses a dedicated `.lock` inode alongside the data file. The data file is never
/// opened or truncated for locking purposes. The lock file is never removed — only
/// truncated to zero on release — to prevent inode-reuse races.
pub fn with_file_lock<T, F>(file_path: &Path, operation: F) -> LockResult<T>
where
    F: FnOnce() -> LockResult<T>,
{
    // Use a dedicated lock file (e.g. instances.json.lock) — never the data file itself
    let lock_path = file_path.with_extension(
        file_path
            .extension()
            .map(|e| format!("{}.lock", e.to_string_lossy()))
            .unwrap_or_else(|| "lock".to_string()),
    );

    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)?;

    // Acquire exclusive lock (blocking)
    let flock_result = unsafe { flock(lock_file.as_raw_fd(), LOCK_EX) };
    if flock_result != 0 {
        return Err(LockError::SystemError {
            message: format!(
                "Failed to lock file {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            ),
        });
    }

    // Execute the operation while holding the lock
    let result = operation();

    // Lock is automatically released when lock_file goes out of scope (flock released on close)
    // We intentionally do NOT remove the lock file to avoid inode-reuse races
    result
}
