# UID Pool Allocator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace random sandbox ID generation with a proper UID pool allocator so box_id IS the Linux UID (60000-60999), eliminating UID collisions and the broken `uid_for_box` overflow fallback.

**Architecture:** A process-global atomic bitset tracks which UIDs in 60000-60999 are in use. `Isolate::new` allocates from the pool, `Isolate::cleanup`/`Drop` releases back. The judge-service worker uses the same pool. No external state needed - the pool is in-memory per process.

**Tech Stack:** Rust `std::sync::atomic::AtomicU64` for lock-free bitset, no new dependencies.

---

### Task 1: Create UID pool allocator module

**Files:**
- Create: `src/safety/uid_pool.rs`
- Modify: `src/safety/mod.rs`

- [ ] **Step 1: Write the failing tests**

In `src/safety/uid_pool.rs`, add the module with tests first:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use crate::config::types::{IsolateError, Result};

const BASE_UID: u32 = 60000;
const POOL_SIZE: u32 = 1000; // UIDs 60000-60999
const WORDS: usize = (POOL_SIZE as usize + 63) / 64; // 16 x u64 = 1024 bits

static POOL: [AtomicU64; WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; WORDS]
};

/// Allocate a UID from the pool. Returns a UID in 60000-60999.
/// Fails if all 1000 slots are occupied.
pub fn allocate() -> Result<u32> {
    for word_idx in 0..WORDS {
        loop {
            let current = POOL[word_idx].load(Ordering::Relaxed);
            if current == u64::MAX {
                break; // This word is full, try next
            }
            let bit = (!current).trailing_zeros(); // First zero bit
            if bit >= 64 {
                break;
            }
            let slot = word_idx as u32 * 64 + bit;
            if slot >= POOL_SIZE {
                break; // Past the valid range
            }
            let mask = 1u64 << bit;
            // CAS: set the bit atomically
            if POOL[word_idx]
                .compare_exchange_weak(current, current | mask, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(BASE_UID + slot);
            }
            // CAS failed, retry this word
        }
    }
    Err(IsolateError::ResourceLimit(
        "UID pool exhausted: all 1000 sandbox slots are in use".to_string(),
    ))
}

/// Release a UID back to the pool.
/// Panics in debug mode if the UID was not allocated.
pub fn release(uid: u32) {
    if uid < BASE_UID || uid >= BASE_UID + POOL_SIZE {
        log::warn!("release called with out-of-range UID {}, ignoring", uid);
        return;
    }
    let slot = uid - BASE_UID;
    let word_idx = (slot / 64) as usize;
    let bit = slot % 64;
    let mask = 1u64 << bit;
    let prev = POOL[word_idx].fetch_and(!mask, Ordering::Release);
    debug_assert!(
        prev & mask != 0,
        "double-free: UID {} was not allocated",
        uid
    );
}

/// Number of currently allocated UIDs.
pub fn active_count() -> u32 {
    let mut count = 0u32;
    for word_idx in 0..WORDS {
        count += POOL[word_idx].load(Ordering::Relaxed).count_ones();
    }
    count
}

/// Reset the pool (test-only).
#[cfg(test)]
fn reset() {
    for word_idx in 0..WORDS {
        POOL[word_idx].store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_uid_in_valid_range() {
        reset();
        let uid = allocate().unwrap();
        assert!(uid >= 60000 && uid <= 60999, "uid {} out of range", uid);
        release(uid);
    }

    #[test]
    fn allocate_returns_unique_uids() {
        reset();
        let a = allocate().unwrap();
        let b = allocate().unwrap();
        assert_ne!(a, b);
        release(a);
        release(b);
    }

    #[test]
    fn release_makes_uid_available_again() {
        reset();
        let uid = allocate().unwrap();
        release(uid);
        let uid2 = allocate().unwrap();
        assert_eq!(uid, uid2, "released UID should be reallocated first");
        release(uid2);
    }

    #[test]
    fn pool_exhaustion_returns_error() {
        reset();
        let mut uids = Vec::new();
        for _ in 0..1000 {
            uids.push(allocate().unwrap());
        }
        assert!(allocate().is_err());
        for uid in uids {
            release(uid);
        }
    }

    #[test]
    fn active_count_tracks_allocations() {
        reset();
        assert_eq!(active_count(), 0);
        let a = allocate().unwrap();
        assert_eq!(active_count(), 1);
        let b = allocate().unwrap();
        assert_eq!(active_count(), 2);
        release(a);
        assert_eq!(active_count(), 1);
        release(b);
        assert_eq!(active_count(), 0);
    }

    #[test]
    fn out_of_range_release_is_ignored() {
        release(50000); // below range
        release(61000); // above range
        // should not panic
    }
}
```

- [ ] **Step 2: Add module to safety/mod.rs**

In `src/safety/mod.rs`, add:

```rust
pub mod uid_pool;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test uid_pool -- --nocapture`
Expected: All 6 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/safety/uid_pool.rs src/safety/mod.rs
git commit -m "feat: add UID pool allocator for sandbox isolation (60000-60999)"
```

---

### Task 2: Remove `uid_for_box` and wire pool into config

**Files:**
- Modify: `src/config/types.rs` (remove `uid_for_box`)
- Modify: `src/config/config.rs` (remove `uid_for_box` call, accept uid parameter)

- [ ] **Step 1: Remove `uid_for_box` from `IsolateConfig`**

In `src/config/types.rs`, delete the `uid_for_box` method (lines 136-143):

```rust
// DELETE THIS:
pub fn uid_for_box(box_id: u32) -> u32 {
    const BASE_UID: u32 = 60000;
    const MAX_BOX_ID: u32 = 999;
    if box_id > MAX_BOX_ID {
        return 65534;
    }
    BASE_UID + box_id
}
```

- [ ] **Step 2: Update `with_language_defaults` in config.rs**

In `src/config/config.rs`, replace the `uid_for_box` call (lines 150-156) with pool allocation:

```rust
// REPLACE THIS block inside with_language_defaults:
//   if let Some(box_id_str) = config.instance_id.strip_prefix("rustbox/") {
//       if let Ok(box_id) = box_id_str.parse::<u32>() {
//           let uid = Self::uid_for_box(box_id);
//           config.uid = Some(uid);
//           config.gid = Some(uid);
//       }
//   }

// WITH:
let uid = crate::safety::uid_pool::allocate()?;
config.uid = Some(uid);
config.gid = Some(uid);
```

- [ ] **Step 3: Remove `uid_for_box` tests in config.rs**

Delete the tests `test_uid_for_box_zero`, `test_uid_for_box_max`, `test_uid_for_box_overflow_fallback`, and `test_with_language_defaults_derives_per_box_uid` (lines 259-313 in config.rs). These test the removed function.

- [ ] **Step 4: Update remaining tests that reference uid_for_box values**

In `src/config/config.rs` tests, the `test_with_language_defaults_loads_java_environment` and similar tests don't reference uid_for_box directly but the uid/gid values will change. These tests check environment loading, not UID values, so they should still pass. Verify.

- [ ] **Step 5: Run tests**

Run: `cargo test config -- --nocapture`
Expected: All config tests pass (minus the 4 deleted uid_for_box tests).

- [ ] **Step 6: Commit**

```bash
git add src/config/types.rs src/config/config.rs
git commit -m "refactor: replace uid_for_box with pool-allocated UIDs"
```

---

### Task 3: Wire pool release into Isolate cleanup

**Files:**
- Modify: `src/runtime/isolate.rs`

The UID must be released back to the pool when the sandbox is cleaned up or dropped.

- [ ] **Step 1: Release UID in `Isolate::cleanup`**

In `src/runtime/isolate.rs`, add UID release to the `cleanup` method (around line 567). Before the existing cleanup logic:

```rust
pub fn cleanup(mut self) -> Result<()> {
    let instance_id = self.instance.config.instance_id.clone();

    // Release pool-allocated UID
    if let Some(uid) = self.instance.config.uid {
        crate::safety::uid_pool::release(uid);
    }

    // ... rest of existing cleanup
```

- [ ] **Step 2: Release UID in `Drop` impl**

In the `Drop` impl for `Isolate` (around line 752), add UID release:

```rust
impl Drop for Isolate {
    fn drop(&mut self) {
        self.wipe_workdir_contents();
        // Release pool-allocated UID if cleanup wasn't called explicitly
        if let Some(uid) = self.instance.config.uid {
            if uid >= 60000 && uid <= 60999 {
                crate::safety::uid_pool::release(uid);
                // Prevent double-release if cleanup is called after drop
                self.instance.config.uid = None;
            }
        }
        self.release_lock();
    }
}
```

- [ ] **Step 3: Prevent double-release in cleanup**

In `cleanup`, after releasing the UID, set it to None:

```rust
if let Some(uid) = self.instance.config.uid {
    crate::safety::uid_pool::release(uid);
    self.instance.config.uid = None;  // prevent double-release in Drop
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -- --nocapture`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/runtime/isolate.rs
git commit -m "feat: release pool-allocated UID on sandbox cleanup and drop"
```

---

### Task 4: Update judge-service worker to use pool

**Files:**
- Modify: `judge-service/src/worker.rs`

- [ ] **Step 1: Replace `fastrand::u32` with pool allocation in `execute_in_sandbox`**

In `judge-service/src/worker.rs`, replace the sandbox_id generation (line 137):

```rust
// REPLACE THIS:
// let sandbox_id = fastrand::u32(10000..u32::MAX).to_string();

// WITH:
let sandbox_uid = match rustbox::safety::uid_pool::allocate() {
    Ok(uid) => uid,
    Err(e) => {
        let _ = db.mark_error(job_id, "sandbox pool exhausted").await;
        error!(%job_id, error = %e, "UID pool exhausted");
        return;
    }
};
let sandbox_id = sandbox_uid.to_string();
```

- [ ] **Step 2: Release UID after execution completes**

The `Isolate::cleanup()` call at `worker.rs:265` (`let _ = isolate.cleanup()`) already releases the UID via Task 3. However, if execution errors before `Isolate` is created, the UID was never allocated by `Isolate::new` (it allocates via `with_language_defaults`).

Wait - there's a conflict. Currently `with_language_defaults` will allocate a UID from the pool (Task 2), AND the worker also allocates. That's a double allocation.

**Fix:** Remove the pool allocation from `execute_in_sandbox`. The UID is allocated inside `IsolateConfig::with_language_defaults` (Task 2) and released by `Isolate::cleanup`/`Drop` (Task 3). The worker just needs to extract the allocated box_id from the config for `mark_running`:

```rust
fn execute_in_sandbox(
    language: &str,
    code: &str,
    stdin: &str,
) -> Result<ExecutionOutput, String> {
    // ... INIT block stays the same ...

    let config = IsolateConfig::with_language_defaults(language, "rustbox/auto".to_string())
        .map_err(|e| format!("config error: {e}"))?;

    let sandbox_id = config.uid.map(|u| u.to_string()).unwrap_or_default();

    let mut isolate =
        Isolate::new(config).map_err(|e| format!("isolate creation error: {e}"))?;

    // ... rest unchanged, isolate.cleanup() releases the UID ...
```

- [ ] **Step 3: Update `process_job` to not pass sandbox_id from outside**

In `process_job` (line 136), remove the external sandbox_id generation:

```rust
async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str) {
    if let Err(e) = db.mark_running(job_id, node_id, "pending").await {
        error!(%job_id, error = %e, "failed to mark running, aborting");
        return;
    }

    // ... get submission ...

    let language = submission.language.clone();
    let code = submission.code.clone();
    let stdin = submission.stdin.clone();

    let result =
        tokio::task::spawn_blocking(move || execute_in_sandbox(&language, &code, &stdin))
            .await;

    // ... rest unchanged ...
```

Update `execute_in_sandbox` signature to drop `sandbox_id` parameter:

```rust
fn execute_in_sandbox(
    language: &str,
    code: &str,
    stdin: &str,
) -> Result<ExecutionOutput, String> {
```

- [ ] **Step 4: Update `mark_running` call with actual sandbox_id after allocation**

Actually, we need the sandbox_id for the DB record. Since it's allocated inside `execute_in_sandbox`, return it alongside the result:

```rust
fn execute_in_sandbox(
    language: &str,
    code: &str,
    stdin: &str,
) -> Result<(ExecutionOutput, String), String> {
    // ...
    let sandbox_id = config.uid.map(|u| u.to_string()).unwrap_or_default();
    // ...
    Ok((output, sandbox_id))
}
```

Then in `process_job`, call `mark_running` before execution with a placeholder, or restructure to pass sandbox_id back. The simplest approach: mark running first with "allocating", then update sandbox_id after allocation. Or just accept that `mark_running` happens before we know the sandbox_id and update it after.

The cleanest approach: keep `mark_running` with a placeholder, then the completed/error update captures the final state:

```rust
async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str) {
    if let Err(e) = db.mark_running(job_id, node_id, "allocating").await {
        error!(%job_id, error = %e, "failed to mark running, aborting");
        return;
    }

    let submission = match db.get_submission(job_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(%job_id, "submission not found in database");
            let _ = db.mark_error(job_id, "submission vanished from database").await;
            return;
        }
        Err(e) => {
            error!(%job_id, error = %e, "database read error");
            let _ = db.mark_error(job_id, &format!("database read error: {e}")).await;
            return;
        }
    };

    let language = submission.language.clone();
    let code = submission.code.clone();
    let stdin = submission.stdin.clone();

    let result =
        tokio::task::spawn_blocking(move || execute_in_sandbox(&language, &code, &stdin))
            .await;

    match result {
        Ok(Ok(output)) => {
            if let Err(e) = db.mark_completed(job_id, &output).await {
                error!(%job_id, error = %e, "failed to store result");
                let _ = db.mark_error(job_id, "execution succeeded but result storage failed").await;
            } else {
                info!(%job_id, verdict = output.verdict, "submission completed");
            }
        }
        Ok(Err(e)) => {
            error!(%job_id, error = %e, "execution failed");
            let _ = db.mark_error(job_id, &sanitize_error(&e)).await;
        }
        Err(e) => {
            error!(%job_id, error = %e, "worker task panicked");
            let _ = db.mark_error(job_id, "internal execution error").await;
        }
    }
}
```

- [ ] **Step 5: Run judge-service tests**

Run: `cargo test -p judge-service -- --nocapture`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add judge-service/src/worker.rs
git commit -m "refactor: use UID pool allocator in judge-service worker"
```

---

### Task 5: Update CLI box_id to use pool when not explicitly provided

**Files:**
- Modify: `src/cli.rs`

The CLI `--box-id` flag stays u32 for manual use, but `execute-code` should optionally auto-allocate from the pool.

- [ ] **Step 1: Update `Commands::ExecuteCode` to auto-allocate box_id from pool**

In the `ExecuteCode` handler (line 504), after config creation, the UID is already pool-allocated by `with_language_defaults` (Task 2). The `--box-id` is used for instance_id (`rustbox/{box_id}`) and lock files. The instance_id now needs to use the pool-allocated UID:

```rust
// In ExecuteCode handler, after language normalization:
// The box_id from CLI is used for instance_id naming only.
// The actual UID comes from the pool via with_language_defaults.
let mut config = crate::config::types::IsolateConfig::with_language_defaults(
    &language,
    format!("rustbox/{}", box_id),
)?;
```

This already works because `with_language_defaults` allocates from the pool regardless of the instance_id string. The `--box-id` is just a namespace for the instance directory, not the UID.

No code change needed here - the pool allocation in `with_language_defaults` (Task 2) handles it.

- [ ] **Step 2: Verify the `Init` and `Run` commands still work**

`Init` creates an `IsolateConfig` with `..Default::default()` which sets `uid: Some(65534)`. This does NOT go through `with_language_defaults`, so no pool allocation happens. This is correct - `init`/`run` are low-level commands that don't need pool UIDs.

- [ ] **Step 3: Run full test suite**

Run: `cargo test --all -- --nocapture`
Expected: All tests pass.

- [ ] **Step 4: Commit (if any changes were needed)**

```bash
git commit -m "chore: verify CLI integration with UID pool" --allow-empty
```

---

### Task 6: Update `force_cleanup_box_resources` in lock_manager

**Files:**
- Modify: `src/safety/lock_manager.rs`

- [ ] **Step 1: Fix UID-based process kill to use the actual allocated UID**

In `force_cleanup_box_resources` (line 357), the current code computes `60000 + box_id`. Since box_id now IS the UID (from the pool), this is a double-add. Fix:

```rust
fn force_cleanup_box_resources(&self, box_id: u32) -> LockResult<()> {
    warn!("Force cleaning up resources for box {}", box_id);
    let instance_id = format!("rustbox/{}", box_id);

    // box_id IS the UID when allocated from pool (60000-60999 range)
    // For legacy box IDs outside the pool range, compute the UID
    let sandbox_uid = if box_id >= 60000 && box_id <= 60999 {
        box_id
    } else {
        60000_u32.saturating_add(box_id).min(60999)
    };

    if sandbox_uid >= 60000 && sandbox_uid <= 60999 {
        // ... existing /proc scan and kill logic using sandbox_uid ...
```

Wait - this reveals a design issue. The lock manager's `box_id` comes from `extract_box_id` which strips `"rustbox/"` prefix and parses as u32. If instance_id is `"rustbox/60042"`, box_id = 60042, which IS the UID. So `60000 + 60042 = 120042` is wrong.

The fix is simpler - just use `box_id` directly instead of `60000 + box_id`:

```rust
// REPLACE:
// let sandbox_uid = 60000_u32.saturating_add(box_id);

// WITH:
let sandbox_uid = box_id;
```

But this only works for pool-allocated box_ids (60000-60999). For legacy/manual box_ids (0-999 from CLI), the old formula was correct.

Safest fix: check the range:

```rust
let sandbox_uid = if box_id >= 60000 && box_id <= 60999 {
    box_id // Pool-allocated: box_id IS the UID
} else {
    60000_u32.saturating_add(box_id) // Legacy: derive UID from box_id
};
```

- [ ] **Step 2: Release the UID back to pool in force_cleanup**

After killing orphaned processes and cleaning up cgroup/state, release the UID:

```rust
// At end of force_cleanup_box_resources, before the Ok(()):
if sandbox_uid >= 60000 && sandbox_uid <= 60999 {
    crate::safety::uid_pool::release(sandbox_uid);
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test lock_manager -- --nocapture`
Expected: All lock_manager tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/safety/lock_manager.rs
git commit -m "fix: correct UID computation in force_cleanup for pool-allocated box_ids"
```

---

### Task 7: Integration test

**Files:**
- Create: `tests/uid_pool_integration.rs`

- [ ] **Step 1: Write integration test verifying pool lifecycle**

```rust
use rustbox::safety::uid_pool;

#[test]
fn pool_allocate_release_cycle() {
    let uid = uid_pool::allocate().expect("should allocate");
    assert!(uid >= 60000 && uid <= 60999);
    let count = uid_pool::active_count();
    assert!(count >= 1);
    uid_pool::release(uid);
}

#[test]
fn concurrent_allocations_are_unique() {
    use std::sync::Arc;
    use std::thread;

    let allocated = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for _ in 0..50 {
        let allocated = allocated.clone();
        handles.push(thread::spawn(move || {
            let uid = uid_pool::allocate().expect("should allocate");
            allocated.lock().unwrap().push(uid);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let uids = allocated.lock().unwrap();
    let unique: std::collections::HashSet<_> = uids.iter().collect();
    assert_eq!(uids.len(), unique.len(), "all UIDs must be unique");

    // Cleanup
    for uid in uids.iter() {
        uid_pool::release(*uid);
    }
}
```

- [ ] **Step 2: Run integration test**

Run: `cargo test --test uid_pool_integration -- --nocapture`
Expected: Both tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/uid_pool_integration.rs
git commit -m "test: add UID pool integration and concurrency tests"
```
