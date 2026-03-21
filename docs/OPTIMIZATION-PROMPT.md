# Rustbox Optimization Prompt

Copy everything below the line into a fresh session.

---

## Task

You are continuing a performance and codebase minimization effort on **rustbox** (`/home/kai/code/orkait/rustbox`). The goal is to make the codebase as small, fast, and clean as possible **without breaking sandbox correctness or existing features**.

**Branch:** `refactor/aggressive-minimization` (already checked out)

**Current state:** 15,329 lines across 53 .rs files. Two prior passes already removed ~2,360 lines (from 17,689). All 144 unit tests pass. Zero clippy warnings.

**Pre-existing test failures:** 7-8 integration tests (`cargo test --test integration_execution`) fail due to environment issues (missing C++/Java compilers). These are NOT caused by the optimization work - they fail on main too. Ignore them.

## Instructions

### 1. Load skills first

Load `/home/kai/skills/rust-skill` (read SKILL.md + relevant chapter references before making changes). Apply its guidelines on:
- Borrowing over cloning (Chapter 1)
- Performance (Chapter 3)
- Error handling (Chapter 4)
- Anti-patterns (references/m15-anti-pattern.md)
- Zero-cost abstractions (references/m04-zero-cost.md)

Then invoke `/behaviour-analysis` skill to audit the system as a state machine - check every action x state combination for correctness.

### 2. What was already done (do NOT repeat)

**Pass 1 - Dead code & structure:**
- Removed `testing/` module (637 lines, zero usage)
- Removed `config/policy/proc_sys.rs` + `userns.rs` (518 lines, zero usage)
- Gutted `audit.rs` from 870 to 195 lines (kept only 2 of 19 functions actually called)
- Removed deprecated `DirectoryBinding::parse()` (44 lines)
- Deduplicated language adapter profiles via shared `base_profile()` in `languages/mod.rs`
- Extracted `VerdictClassifier::provenance()` helper (cut classifier from 604 to 287 lines)
- Removed unused `MinimalResult`, `create_capability_report_from_evidence()`, `validate_environment_safety()`
- Fixed all clippy warnings (derivable defaults, collapsible ifs, fn pointer casts)

**Pass 2 - Performance & rust-skill audit:**
- Fixed 6 `from_utf8_lossy().to_string()` -> `.into_owned()` (proxy.rs, supervisor.rs, types.rs)
- Refactored supervisor control loop (reduced clone boilerplate, added `Vec::with_capacity`)
- Removed unused `SignalHandler::reset()` method
- Trimmed `BoxLock` struct from 5 fields to 2 (RAII-only fields kept)
- Removed unused `get_metadata()` HashMap builder from presets

### 3. What remains (your targets)

**Largest files still ripe for reduction:**

| File | Lines | Why it's big |
|---|---|---|
| `kernel/mount/filesystem.rs` | 1,136 | 19 functions, mount setup/teardown |
| `cli.rs` | 1,043 | 20 functions, CLI dispatch + helpers |
| `exec/preexec.rs` | 907 | 8 functions, type-state pre-exec chain |
| `core/supervisor.rs` | 901 | Process lifecycle, wait loop, evidence building |
| `safety/lock_manager.rs` | 879 | File locking + cleanup thread |
| `runtime/isolate.rs` | 848 | Sandbox CRUD + execution dispatch |
| `config/types.rs` | 833 | All shared types |

**Known remaining opportunities (from prior audit):**
- **40+ unnecessary `.clone()` calls** across the codebase (especially isolate.rs, executor.rs, json_schema.rs, core/types.rs)
- **~49 literal `.to_string()` in presets.rs** for envelope registration (could use `&'static str` fields on LanguageEnvelope if Deserialize constraint is lifted)
- **Supervisor string allocations** - "hardened", "default", "disabled", "clean" etc. as `.to_string()` on every execution
- **config/validator.rs (533 lines)** - check if all validations are actively used
- **runtime/security.rs (391 lines)** - check for overlap with env_hygiene.rs
- **HashMap for 5-entry LanguagePresets** - could be an array or match

**Behaviour analysis findings (minor, all acceptable):**
- Signal cleanup race during the cleanup phase itself (extremely unlikely, recoverable)
- `Isolate::cleanup()` is NOT idempotent on second call (returns "not found" error - acceptable)
- Pre-exec type-state chain is not used in the proxy path (manual ordering instead)
- Baseline corruption recovery silently loses existing sandbox entries

### 4. Rules

- **Create checkpoint commits after each change** (after tests pass)
- **Run `cargo test --lib` after every change** - all 144 tests must pass
- **Run `cargo clippy -- -D warnings`** - must stay clean
- **Do NOT break sandbox correctness** - type-state chain, kernel primitives, cgroup enforcement, signal handling must all remain intact
- **Do NOT add features** - only reduce, simplify, optimize
- **Measure before/after** - track line count and report at the end
- **Focus on code reduction AND performance** - prefer removing dead code and reducing allocations over restructuring working code
- **`preexec.rs` is sacred** - the type-state chain is the core safety mechanism. Optimize within it, don't restructure it
- **`fork_safe_log.rs` is justified** - async-signal-safe logging post-fork. Don't touch it.

### 5. Verification

When done, report:
1. Line count before/after
2. Files removed (if any)
3. Test results (`cargo test --lib`)
4. Clippy results
5. Git log of all commits on this branch
