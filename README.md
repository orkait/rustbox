# rustbox

A secure process isolation and resource control system inspired by IOI Isolate, designed for safe execution of untrusted code with comprehensive sandbox capabilities.

## 🔒 Security Features

- **Namespace Isolation**: PID, mount, network, and user namespace separation
- **Resource Limits**: Memory, CPU, file size, and execution time enforcement  
- **Filesystem Isolation**: Chroot-based filesystem containment
- **Cgroups Support**: Resource enforcement using cgroups v1 for maximum compatibility
- **Path Validation**: Directory traversal attack prevention
- **Memory Safety**: Rust implementation eliminates entire classes of security vulnerabilities

## 🚀 Quick Start

```bash
# Initialize a sandbox
rustbox init --box-id 0

# Run code with resource limits
rustbox run --box-id 0 --mem 128 --time 10 /usr/bin/python3 solution.py

# Cleanup sandbox
rustbox cleanup --box-id 0
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
```

### Using Debian Package

```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/rustbox_*.deb
```

## 📖 Usage

### Basic Commands

```bash
# Initialize sandbox environment
rustbox init --box-id <ID>

# Execute program with limits
rustbox run --box-id <ID> [OPTIONS] <COMMAND> [ARGS...]

# Clean up sandbox
rustbox cleanup --box-id <ID>

# Get system status
rustbox status
```

### Resource Limit Options

```bash
rustbox run --box-id 0 \
  --mem 256          # Memory limit in MB
  --time 30          # CPU time limit in seconds  
  --wall-time 60     # Wall clock time limit in seconds
  --fsize 10         # File size limit in MB
  --processes 10     # Process count limit
  /usr/bin/python3 script.py
```

### Advanced Isolation

```bash
rustbox run --box-id 0 \
  --isolate-pids     # PID namespace isolation
  --isolate-net      # Network isolation  
  --isolate-fs       # Filesystem isolation
  --chroot /path     # Custom chroot directory
  /usr/bin/gcc program.c
```

## 🏗️ Project Structure

```
rustbox/
├── src/                    # Core implementation
│   ├── main.rs            # CLI interface and command handling
│   ├── isolate.rs         # Core sandbox logic
│   ├── executor.rs        # Process execution management
│   ├── filesystem.rs      # Filesystem isolation
│   ├── namespace.rs       # Linux namespace management
│   ├── cgroup.rs          # Cgroups resource control
│   ├── io_handler.rs      # Input/output redirection
│   └── types.rs           # Shared type definitions
├── tests/                 # Comprehensive test suite
│   ├── core/              # Basic functionality tests
│   ├── security/          # Security and isolation tests
│   ├── resource/          # Resource limit validation
│   ├── stress/            # Load and scalability tests
│   ├── performance/       # Performance benchmarks
│   └── integration/       # End-to-end workflow tests
├── test_programs/         # Sample programs for testing
├── systemd/               # Service configuration files
└── debian/                # Debian packaging scripts
```

## 🧪 Testing

### Run Test Suites

```bash
# All tests (requires sudo)
sudo ./run_tests.sh

# Specific test categories
sudo ./tests/run_category.sh core
sudo ./tests/run_category.sh security  
sudo ./tests/run_category.sh stress

# Individual tests
sudo ./tests/core/quick_core_test.sh
sudo ./tests/security/isolation_test.sh
```

### Test Categories

- **Core Tests**: Essential functionality validation
- **Security Tests**: Isolation and containment verification
- **Resource Tests**: Resource limit enforcement
- **Stress Tests**: Load testing and scalability
- **Performance Tests**: Benchmark measurements
- **Integration Tests**: End-to-end workflows

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

# Integration tests (requires sudo)
sudo ./run_tests.sh

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