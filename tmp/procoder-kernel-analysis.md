# Procoder Analysis: Kernel Module Refactoring

## Task Classification
**Type**: Refactor (behavior preserved)
**Scope**: src/kernel module
**Goal**: Apply SDE-3 engineering principles for long-term maintainability

---

## Step 1: Current Architecture Assessment

### Module Structure
```
kernel/
├── mod.rs              # Module exports
├── capabilities.rs     # Privilege management (450 LOC)
├── namespace.rs        # Namespace isolation (250 LOC)
├── signal.rs           # Signal handling (210 LOC)
├── cgroup/
│   ├── mod.rs
│   ├── backend.rs      # Trait abstraction
│   ├── v1.rs
│   └── v2.rs
└── mount/
    ├── mod.rs
    └── filesystem.rs   # Filesystem isolation (870 LOC)
```

### Responsibilities (Current)
1. **capabilities.rs**: Capability drops, UID/GID transitions, privilege management
2. **namespace.rs**: Namespace isolation, loopback setup
3. **signal.rs**: Async-safe signal handling
4. **cgroup/**: Resource governance (v1/v2 abstraction)
5. **mount/**: Filesystem isolation, chroot, device nodes

---

## Step 2: Invariants & Constraints

### Critical Invariants
1. **Ordering**: setresgid MUST precede setresuid
2. **Atomicity**: Capability drops must be all-or-nothing
3. **Async-safety**: Signal handlers only use atomic operations
4. **Mount propagation**: MS_PRIVATE before any mount mutations
5. **No partial state**: Cleanup on failure must be complete

### Current Violations
1. ❌ **capabilities.rs**: Mixed concerns (capabilities + UID/GID)
2. ❌ **filesystem.rs**: 870 LOC violates single responsibility
3. ❌ **No explicit error recovery**: Cleanup paths not centralized
4. ❌ **Implicit dependencies**: Ordering not enforced by types
5. ❌ **Test coverage**: No behavior-locking tests visible

---

## Step 3: Refactoring Strategy

### Principle: Preserve Correctness First
- No behavior changes
- Add tests before structural changes
- Explicit module boundaries
- Clear dependency direction

### Module Decomposition

#### Current Problem: capabilities.rs (450 LOC, 2 responsibilities)
```rust
// MIXED CONCERNS:
- Capability management (drop_all_capabilities, etc.)
- Credential management (transition_to_unprivileged, etc.)
```

#### Solution: Split by Responsibility
```
kernel/
├── capabilities/
│   ├── mod.rs          # Public API
│   ├── drop.rs         # Capability dropping logic
│   └── query.rs        # Capability inspection
├── credentials/
│   ├── mod.rs          # Public API
│   ├── transition.rs   # UID/GID transitions
│   └── validation.rs   # Credential validation
```

**Rationale**: 
- Single responsibility per module
- Clear ownership boundaries
- Easier to test in isolation
- Explicit dependency direction (credentials depends on capabilities, not vice versa)

#### Current Problem: filesystem.rs (870 LOC, 5+ responsibilities)
```rust
// MIXED CONCERNS:
- Chroot setup
- Device node creation
- Mount operations
- Directory bindings
- Path validation
```

#### Solution: Extract by Concern
```
kernel/mount/
├── mod.rs              # Public API
├── filesystem.rs       # High-level orchestration (200 LOC)
├── chroot.rs           # Chroot operations
├── devices.rs          # Device node management
├── bindings.rs         # Directory binding logic
└── validation.rs       # Path validation
```

**Rationale**:
- Each file < 300 LOC
- One reason to change per file
- Testable in isolation
- Clear module boundaries

---

## Step 4: Public API Design

### Principle: Minimal Surface, Explicit Contracts

#### capabilities/ Public API
```rust
// kernel/capabilities/mod.rs
pub use drop::drop_all_capabilities;
pub use query::{get_bounding_set, get_capability_status};

pub struct CapabilityNumber(u32);
pub enum CapabilitySet { /* ... */ }

// INVARIANT: All capability operations are idempotent
// INVARIANT: Partial drops are acceptable (best-effort)
```

#### credentials/ Public API
```rust
// kernel/credentials/mod.rs
pub use transition::transition_to_unprivileged;
pub use validation::validate_ids;

// INVARIANT: setresgid MUST be called before setresuid
// INVARIANT: Root UIDs/GIDs are rejected in strict mode
// ORDERING: Must be called AFTER capability drops
```

#### mount/ Public API
```rust
// kernel/mount/mod.rs
pub use filesystem::FilesystemSecurity;
pub use chroot::ChrootJail;
pub use devices::DeviceNode;

// INVARIANT: Mount propagation MUST be private before mutations
// INVARIANT: Cleanup is idempotent
// ORDERING: Must be called AFTER namespace setup
```

---

## Step 5: Dependency Direction

### Explicit Dependency Graph
```
signal (no deps)
  ↓
namespace (no deps)
  ↓
capabilities (no deps)
  ↓
credentials (depends on: capabilities)
  ↓
mount (depends on: namespace)
  ↓
cgroup (no deps, parallel to mount)
```

**Rules**:
- No circular dependencies
- Lower layers don't know about upper layers
- Dependencies flow downward only

---

## Step 6: Error Recovery Strategy

### Current Problem: Scattered Cleanup
```rust
// Cleanup logic is implicit and scattered
// No centralized error recovery
```

### Solution: Explicit Cleanup Trait
```rust
// kernel/cleanup.rs
pub trait Cleanup {
    /// Cleanup resources, idempotent
    fn cleanup(&mut self) -> Result<()>;
    
    /// Check if cleanup is needed
    fn needs_cleanup(&self) -> bool;
}

// Each module implements Cleanup
impl Cleanup for FilesystemSecurity { /* ... */ }
impl Cleanup for NamespaceIsolation { /* ... */ }
```

**Rationale**:
- Explicit cleanup contract
- Testable in isolation
- Idempotent by design
- Centralized error recovery

---

## Step 7: Testing Strategy

### Behavior-Locking Tests (Required Before Refactor)

#### Unit Tests (Per Module)
```rust
// capabilities/drop_tests.rs
#[test]
fn drop_capabilities_is_idempotent() { /* ... */ }

#[test]
fn drop_capabilities_handles_missing_caps() { /* ... */ }

// credentials/transition_tests.rs
#[test]
fn transition_rejects_root_in_strict_mode() { /* ... */ }

#[test]
fn transition_enforces_gid_before_uid() { /* ... */ }
```

#### Integration Tests (Cross-Module)
```rust
// tests/kernel_integration.rs
#[test]
fn full_privilege_drop_sequence() {
    // Test: capabilities → credentials → verification
}

#[test]
fn cleanup_on_failure() {
    // Test: Partial setup → failure → cleanup verification
}
```

#### Property Tests (Invariants)
```rust
// tests/kernel_properties.rs
#[quickcheck]
fn capability_drop_preserves_process_state(cap: u32) {
    // Property: Dropping capabilities doesn't crash process
}
```

---

## Step 8: Refactoring Plan (Phased)

### Phase 1: Add Tests (No Code Changes)
1. Add unit tests for each public function
2. Add integration tests for sequences
3. Add property tests for invariants
4. **Gate**: All tests pass

### Phase 2: Extract Credentials Module
1. Create `kernel/credentials/` directory
2. Move UID/GID functions from capabilities.rs
3. Update imports
4. Run tests
5. **Gate**: All tests still pass

### Phase 3: Split Filesystem Module
1. Create `kernel/mount/chroot.rs`
2. Create `kernel/mount/devices.rs`
3. Create `kernel/mount/bindings.rs`
4. Extract functions, update imports
5. Run tests
6. **Gate**: All tests still pass

### Phase 4: Add Cleanup Trait
1. Define `Cleanup` trait
2. Implement for each module
3. Add cleanup tests
4. **Gate**: All tests pass

### Phase 5: Documentation
1. Document public APIs
2. Document invariants
3. Document ordering requirements
4. Update architecture docs

---

## Step 9: Risks & Trade-offs

### Risks
1. **Breaking changes**: Refactoring may break downstream code
   - **Mitigation**: Preserve public API, only change internal structure
   
2. **Test coverage gaps**: Missing tests may hide regressions
   - **Mitigation**: Add tests before refactoring (Phase 1)
   
3. **Ordering violations**: Module splits may break implicit ordering
   - **Mitigation**: Document dependencies, add compile-time checks

### Trade-offs
1. **More files vs. simpler files**
   - Trade: Navigation complexity
   - Gain: Easier to understand, test, modify
   
2. **Explicit cleanup vs. RAII**
   - Trade: Manual cleanup calls
   - Gain: Explicit error recovery, no destructor surprises
   
3. **Module granularity vs. cohesion**
   - Trade: More imports
   - Gain: Clear boundaries, single responsibility

---

## Step 10: Non-Goals

1. ❌ **Performance optimization**: Not changing algorithms
2. ❌ **Feature additions**: Behavior preserved only
3. ❌ **API redesign**: Public API stays compatible
4. ❌ **Platform support**: Linux-only, no new platforms
5. ❌ **Dependency changes**: No new external crates

---

## Step 11: Assumptions

### Input Assumptions
1. Code runs on Linux only
2. Root privileges available for tests
3. Kernel >= 3.10 (namespace support)
4. No concurrent modifications during refactor

### State Invariants
1. Capability drops are idempotent
2. UID/GID transitions are atomic
3. Mount operations are reversible
4. Signal handlers are async-safe

### Ordering Guarantees
1. setresgid before setresuid
2. Mount propagation before mount mutations
3. Namespace setup before filesystem isolation
4. Capability drops before credential transitions

---

## Decision: Proceed with Refactoring?

### Checklist
- [ ] Tests exist for current behavior
- [ ] Public API is documented
- [ ] Dependencies are explicit
- [ ] Cleanup strategy is defined
- [ ] Risks are acceptable

**Status**: ⚠️ **BLOCKED** - Need tests before refactoring

**Next Action**: Implement Phase 1 (Add Tests)
