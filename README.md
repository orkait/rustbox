# rustbox

A secure process isolation and resource control system inspired by IOI Isolate, designed for judge-grade execution of untrusted code in competitive programming environments.

**Current Status**: Judge-V1 Development (v0.1.0)  
**Scope**: Deliberately narrow focus on deterministic, kernel-enforced isolation for programming contest judging systems.

## Judge-V1 Scope

Rustbox v1 is **not** a general-purpose sandbox or an isolate drop-in replacement. It is purpose-built for judge-grade execution with:

- Hard process/filesystem isolation for submission runs
- Deterministic resource enforcement and status reporting
- Deterministic lifecycle cleanup with no leftovers
- Stable semantics across cgroup v1/v2 environments
- Evidence-backed verdict provenance for appeals
- Minimal CLI surface and operator-friendly defaults

### Explicitly Deferred Until Post-V1
- WASM execution backend
- eBPF observability features beyond basic metrics
- CRIU/snapshot workflows
- Remote attestation
- Pluggable policy engines
- Dynamic syscall filtering tuning systems
- Multi-tenant scheduling/orchestration layers

See `plan.md` Section 1.1 for complete scope definition.

## 🔒 Security Features

- **Namespace Isolation**: PID, mount, network, and user namespace separation
- **Resource Limits**: Memory, CPU, file size, and execution time enforcement  
- **Filesystem Isolation**: Chroot-based filesystem containment
- **Cgroups Support**: Resource enforcement using cgroups v1 for maximum compatibility
- **Path Validation**: Directory traversal attack prevention
- **Memory Safety**: Rust implementation eliminates entire classes of security vulnerabilities

## 🚀 Quick Start

```bash
# Core sandbox lifecycle (isolate binary)
isolate init --box-id 0

# Run command with resource limits
isolate run --box-id 0 --mem 128 --time 10 /usr/bin/python3 solution.py

# Cleanup sandbox
isolate cleanup --box-id 0

# Language adapter entrypoint (judge binary)
judge execute-code --strict --box-id 10 --language python --code 'print(1)'
```

## 📋 Requirements

- **Operating System**: Linux with cgroups v1 support (primary), Unix-like systems (limited functionality)
- **Privileges**: Root access required for namespace and resource management
- **Dependencies**: 
  - Rust 1.70+ (for building)
  - systemd (for service management)
  - Python 3 (for test programs)

## 🛠️ Installation

### From Source

```bash
git clone <repository-url>
cd rustbox
cargo build --release
sudo cp target/release/rustbox /usr/bin/
sudo cp target/release/isolate /usr/bin/
sudo cp target/release/judge /usr/bin/
```

### Using Debian Package

```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/rustbox_*.deb
```

### MCP Bootstrap (WSL)

For teammates using Kiro/Codex MCP integration with this repo:

```bash
./scripts/bootstrap-mcp.sh
```

This command initializes `tools/codegraphcontext` submodule, installs the pinned CGC runtime, builds `tools/rustbox-mcp`, and runs smoke checks.

After bootstrap, you can run explicit health checks:

```bash
./scripts/mcp/healthcheck-rustbox-mcp.sh
./scripts/mcp/healthcheck-cgc-mcp.sh
```

If you update `mcp.json` command/args, restart your Codex/Kiro session so the MCP bridge reloads the new process definition.

## 📖 Usage

### Basic Commands

```bash
# Initialize sandbox environment
isolate init --box-id <ID>

# Execute program with limits
isolate run --box-id <ID> [OPTIONS] <COMMAND> [ARGS...]

# Clean up sandbox
isolate cleanup --box-id <ID>

# Get system status
isolate status
```

### Resource Limit Options

```bash
isolate run --box-id 0 \
  --mem 256          # Memory limit in MB
  --time 30          # CPU time limit in seconds  
  --wall-time 60     # Wall clock time limit in seconds
  --processes 10     # Process count limit
  -- /usr/bin/python3 script.py
```

### Execute-Code Mode

```bash
# Strict mode (root required)
judge execute-code --strict --box-id 10 --language python --code 'print(1)'

# Permissive mode (unsafe for untrusted code; development only)
judge execute-code --permissive --box-id 11 --language python --code 'print(1)'

# Optional syscall filtering gate (currently fail-closed until implemented)
judge execute-code --strict --enable-syscall-filtering --box-id 12 --language python --code 'print(1)'

# Backward-compatible alias still supported
rustbox execute-code --strict --box-id 13 --language python --code 'print(1)'
```

WSL note: C++ compile phase currently runs outside namespaces for toolchain stability; compiled payload execution still runs with isolate defaults.
WSL note: Java currently downgrades to permissive mode and disables PID namespace because the current single-fork PID namespace path blocks JVM thread startup. Capability report reflects this downgrade.

## 🏗️ Project Structure

```
rustbox/
├── src/
│   ├── main.rs            # rustbox compatibility wrapper
│   ├── cli.rs             # shared CLI implementation and mode gating
│   ├── bin/
│   │   ├── isolate.rs     # isolate binary (language-agnostic core surface)
│   │   └── judge.rs       # judge binary (language adapter surface)
│   ├── config/            # Config loading, validation, policy
│   ├── exec/              # Executor, pre-exec chain, supervision
│   ├── kernel/            # Namespaces, cgroups, seccomp, capabilities
│   ├── legacy/            # Compatibility paths kept during migration
│   ├── observability/     # Audit logs, health, metrics, ops checks
│   ├── safety/            # Cleanup, locks, workspace management
│   ├── testing/           # Reusable proof helpers
│   ├── utils/             # JSON schema, env/fd/output utilities
│   └── verdict/           # Envelope, timeout/divergence, abuse classification
├── tests/                 # Integration, adversarial, parity, trybuild
├── docs/                  # ADRs, runbooks, QA/release gates
└── tools/                 # MCP servers and codegraph tooling
```

## 🧪 Testing

### Run Test Suites

```bash
# Full suite
cargo test --all -- --nocapture

# Trybuild typestate compile-fail tests
cargo test --test trybuild

# Targeted runtime checks in WSL
target/debug/judge execute-code --permissive --box-id 1 --language python --code 'print(1)'
wsl -u root -e bash -lc "cd /mnt/c/codingFiles/orkait/rustbox && target/debug/judge execute-code --strict --box-id 2 --language python --code 'print(1)'"
```

### Test Categories

- **Adversarial Security**: breakout, path traversal, containment
- **Failure Matrix**: cleanup/idempotency and baseline equivalence
- **Cgroup Parity**: v1/v2 behavior matrix
- **Schema and Provenance**: audit + JSON stability checks
- **Trybuild**: compile-time typestate invariants

## ⚙️ Configuration

### System Service

Enable as systemd service:

```bash
sudo systemctl enable rustbox
sudo systemctl start rustbox
```

### Language Support

Setup common programming language environments:

```bash
sudo ./setup_languages.sh
```

## 🔧 Development

### Building

```bash
cargo build --release
```

### Running Tests

```bash
# Unit tests
cargo test

# Full verification
cargo test --all -- --nocapture

# Debug logging
RUST_LOG=debug ./target/release/rustbox run --box-id 0 /bin/echo "Hello"
```

### Contributing

1. Follow Rust coding standards
2. Add comprehensive tests for new features
3. Update documentation
4. Ensure all security tests pass
5. Run full test suite before submitting

## 📊 Performance

Typical performance characteristics:

- **Startup Time**: <0.5 seconds
- **Execution Overhead**: <0.2 seconds  
- **Memory Usage**: <10MB base overhead
- **Throughput**: >2 operations/second

## 🔐 Security Considerations

This tool is designed for **defensive security purposes only**:

- Safe execution of untrusted code submissions
- Programming contest environments
- Code analysis and testing
- Educational sandboxing

**Important**: Ensure proper system hardening and monitoring when deploying in production environments.

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🤝 Support

For issues, feature requests, or contributions, please refer to the project's issue tracking system.

## 🙏 Acknowledgments

Inspired by [IOI Isolate](https://github.com/ioi/isolate), the industry-standard sandbox for programming contests and secure code execution.
