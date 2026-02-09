# Rustbox Reference Syscall Catalogs

## ⚠️ CRITICAL WARNINGS

**These catalogs are DESCRIPTIVE ONLY and provide NO GUARANTEES:**

- ❌ **NO compatibility guarantees** - Programs may fail unexpectedly
- ❌ **NO correctness guarantees** - Behavior may be incorrect or incomplete
- ❌ **NO safety guarantees** - Security properties are not validated
- ❌ **NOT recommendations** - These are reference examples only
- ❌ **NOT defaults** - Syscall filtering is disabled by default

**Dynamic runtimes (Python, Java, Node.js, etc.) will likely FAIL with these filters.**

## Purpose

These catalogs serve as **starting points** for advanced users who:
1. Understand syscall filtering deeply
2. Accept full responsibility for compatibility issues
3. Are willing to debug and maintain custom filters
4. Have specific security requirements beyond isolation

## Usage

Syscall filtering is **disabled by default** and requires explicit opt-in:

```bash
# Enable with custom allowlist (recommended for advanced users)
rustbox run --enable-syscall-filtering --syscall-allowlist=custom.json ...

# Enable with reference catalog (use at your own risk)
rustbox run --enable-syscall-filtering --syscall-catalog=x86_64/minimal ...
```

## Architecture Support

- `x86_64/` - x86-64 (AMD64) syscall catalogs
- `arm64/` - ARM64 (AArch64) syscall catalogs

## Catalog Descriptions

### minimal.json

A minimal set of syscalls for basic I/O operations. Suitable for:
- Simple C programs with static linking
- Programs that only do basic file I/O
- Educational purposes

**NOT suitable for:**
- Dynamic runtimes (Python, Java, Node.js, Ruby, etc.)
- Programs using threading
- Programs using complex I/O (async, epoll, etc.)
- Programs using network operations
- Most real-world applications

## Failure Attribution

Per plan.md Section 6.1:

- Failures under enabled syscall filtering are attributed to **filtering/user profile behavior**
- They are **NOT** attributed to judge infrastructure faults
- Rustbox provides no support for debugging filter-induced failures

## Metadata Recording

When syscall filtering is enabled, the following metadata is recorded:

- `syscall_filtering_enabled`: true/false
- `syscall_filtering_source`: "none" | "custom_allowlist" | "reference_catalog"
- `syscall_filtering_profile_id`: Unique identifier for the filter profile
- `execution_envelope_id`: Includes filtering state in hash

## Creating Custom Filters

For production use, create custom allowlists tailored to your specific workload:

```json
{
  "catalog_name": "my-custom-filter",
  "architecture": "x86_64",
  "version": "1.0",
  "description": "Custom filter for my specific use case",
  "syscalls": [
    "read",
    "write",
    "exit_group",
    ...
  ]
}
```

Test thoroughly with your actual workload before deploying.

## Judge-V1 Default Behavior

**Syscall filtering is DISABLED by default in judge-v1.**

This ensures:
- Maximum compatibility with diverse programming languages
- Predictable behavior across different runtime environments
- No silent failures due to missing syscalls
- Isolate-compatible default behavior

Judge-v1 relies on namespace isolation, cgroup limits, and privilege dropping for security, not syscall filtering.

## Support Policy

**Rustbox provides NO support for syscall filtering issues.**

If you enable syscall filtering:
- You are responsible for debugging compatibility issues
- You are responsible for maintaining filter profiles
- You accept that programs may fail in unexpected ways
- You understand that failures are attributed to your filter, not rustbox

## References

- Linux syscall reference: https://man7.org/linux/man-pages/man2/syscalls.2.html
- seccomp-bpf documentation: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- Architecture-specific syscall tables: https://github.com/torvalds/linux/tree/master/arch
