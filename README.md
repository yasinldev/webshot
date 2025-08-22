# WebShot - Network Scanner

[![Rust](https://img.shields.io/badge/Rust-1.70+-red.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/webshot.svg)](https://crates.io/crates/webshot)

WebShot is a high-performance, professional network port scanner and service detector written in Rust. It provides fast, accurate port scanning with service identification, banner grabbing, and comprehensive reporting capabilities.

## ✨ Features

- **Fast Port Scanning**: High-performance TCP/UDP port scanning with configurable concurrency
- **Service Detection**: Automatic service identification and version detection
- **Banner Grabbing**: Extract service banners and response information
- **Multiple Protocols**: Support for both TCP and UDP scanning
- **Domain Resolution**: Automatic DNS resolution for domain names
- **Progress Tracking**: Real-time progress bars and detailed logging
- **Multiple Output Formats**: Human-readable and JSON output options
- **Configurable Timeouts**: Adjustable connection timeouts for different network conditions
- **User Agent Rotation**: Random user agent selection for stealth scanning
- **Comprehensive Logging**: Structured logging with configurable verbosity levels

## 🚀 Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo package manager

### From Source

```bash
# Clone the repository
git clone https://github.com/yasinldev/webshot.git
cd webshot

# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

### From Cargo

```bash
cargo install webshot
```

## 📖 Usage

### Basic Usage

```bash
# Scan a single IP address
webshot 192.168.1.1

# Scan a specific port
webshot 192.168.1.1 80

# Scan a port range
webshot 192.168.1.1 80-443

# Scan all ports
webshot 192.168.1.1 --all

# Scan a domain
webshot example.com 22,80,443,3306
```

### Advanced Options

```bash
# TCP-only scan with custom timeout
webshot 192.168.1.1 1-1024 --tcp --timeout 10

# UDP scan with high concurrency
webshot 192.168.1.1 53,123,161 --udp --concurrency 200

# Random user agents and JSON output
webshot 192.168.1.1 80-443 --random-agent --json

# Verbose output for debugging
webshot 192.168.1.1 22,80,443 --verbose

# Quiet mode (minimal output)
webshot 192.168.1.1 80 --quiet
```

### Subcommands

```bash
# Web service scanning
webshot web https://example.com

# Database service scanning
webshot database mysql

# Specific service scanning
webshot service ssh
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--tcp` | Scan only TCP ports | TCP (default) |
| `--udp` | Scan only UDP ports | TCP (default) |
| `--all` | Scan all ports (1-65535) | 1-1024 |
| `--timeout` | Connection timeout in seconds | 5 |
| `--concurrency` | Number of concurrent connections | 100 |
| `--random-agent` | Use random user agents | false |
| `--json` | Output results in JSON format | false |
| `--verbose` | Verbose output | false |
| `--quiet` | Quiet mode (minimal output) | false |

## 🏗️ Architecture

WebShot is built with a modular, professional architecture:

```
src/
├── main.rs              # CLI entry point and argument parsing
└── scanning/
    ├── mod.rs           # Module organization and re-exports
    ├── config.rs        # Configuration management
    ├── types.rs         # Data structures and types
    ├── scanner.rs       # Main scanning orchestration
    ├── tcp.rs           # TCP/UDP scanning implementation
    ├── dns.rs           # DNS resolution and IP handling
    └── utils.rs         # Utility functions and helpers
```

### Key Components

- **NetworkScanner**: Main orchestrator for port scanning operations
- **ScanConfig**: Configuration management with builder pattern
- **Service Detection**: Intelligent service identification and fingerprinting
- **Concurrency Control**: Semaphore-based connection limiting
- **Progress Tracking**: Real-time progress bars and status updates
- **Error Handling**: Comprehensive error handling with anyhow

## 🔧 Configuration

### Environment Variables

- `RUST_LOG`: Set logging level (error, warn, info, debug, trace)
- `WEBSHOT_TIMEOUT`: Default connection timeout
- `WEBSHOT_CONCURRENCY`: Default concurrency level

### Configuration File

Create a `webshot.toml` file in your home directory:

```toml
[defaults]
timeout = 5
concurrency = 100
random_agent = false
json_output = false

[scanning]
default_ports = [22, 80, 443, 3306, 5432, 6379, 27017]
tcp_timeout = 5
udp_timeout = 10
```

## 📊 Output Formats

### Human-Readable Output

```
╔══════════════════════════════════════════════════════════════╗
║                        WEBSHOT                               ║
║                                                              ║
║  Version: 0.1.0 | Author: yasinldev                          ║
║  Repository: https://github.com/yasinldev/webshot            ║
╚══════════════════════════════════════════════════════════════╝

[INFO] Starting TCP scan of 1024 ports on 192.168.1.1
⠋ [00:00:15] [████████████████████████████████████████] 512/1024 (00:00:15)

Scan Results:
================================================================================
[OPEN] [TCP] Port 22 => Service: SSH => Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[OPEN] [TCP] Port 80 => Service: HTTP Server => Banner: HTTP/1.1 200 OK
[OPEN] [TCP] Port 443 => Service: HTTP Server => Banner: HTTP/1.1 200 OK
================================================================================
Total open ports: 3 found
```

### JSON Output

```json
[
  {
    "port": 22,
    "protocol": "TCP",
    "is_open": true,
    "service": "SSH",
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "target_ip": "192.168.1.1",
    "hostname": null,
    "timestamp": "2024-01-15T10:30:00Z"
  }
]
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test scanning::tcp

# Run tests with coverage (requires cargo-tarpaulin)
cargo tarpaulin
```

## 📈 Performance

WebShot is designed for high performance:

- **Concurrent Scanning**: Configurable concurrency up to 1000+ connections
- **Efficient Memory Usage**: Minimal memory footprint during scanning
- **Fast DNS Resolution**: Async DNS resolution with caching
- **Optimized Network I/O**: Non-blocking I/O operations
- **Progress Tracking**: Real-time progress updates without performance impact

### Benchmarks

Typical performance on modern hardware:

| Port Range | Concurrency | Time (TCP) | Time (UDP) |
|------------|-------------|------------|------------|
| 1-1024     | 100         | ~2-5s      | ~5-10s     |
| 1-65535    | 500         | ~30-60s    | ~60-120s   |
| 1-1024     | 1000        | ~1-2s      | ~3-5s      |

## 🔒 Security & Legal Notice

**⚠️ IMPORTANT**: WebShot is designed for legitimate network security testing and research purposes only.

- **Legal Use Only**: Only scan networks you own or have explicit permission to test
- **Educational Purpose**: Use for learning network security concepts
- **Professional Testing**: Use for authorized security assessments
- **No Illegal Activity**: Developers are not responsible for any illegal use

### Responsible Disclosure

If you discover security vulnerabilities in WebShot, please:
1. **Do not** exploit them on unauthorized systems
2. Report them privately to the maintainers
3. Allow reasonable time for fixes before public disclosure

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yasinldev/webshot.git
cd webshot

# Install development dependencies
cargo install cargo-watch
cargo install cargo-tarpaulin

# Run development server
cargo watch -x run

# Format code
cargo fmt

# Lint code
cargo clippy
```

### Code Style

- Follow Rust conventions and idioms
- Use meaningful variable and function names
- Add comprehensive documentation
- Include tests for new functionality
- Follow the existing code structure

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Rust Community**: For the excellent ecosystem and tools
- **Network Security Community**: For feedback and testing
- **Open Source Contributors**: For inspiration and code examples
- **Security Researchers**: For advancing network security knowledge