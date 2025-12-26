# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`narcd` is a network threat monitoring daemon that combines eBPF-based packet inspection with SSH and HTTP honeypot capabilities. It monitors network traffic for port scans and logs SSH authentication attempts and HTTP requests, designed to run on Linux systems (particularly AWS EC2 instances).

## Build System

This is a Rust workspace with three crates:
- `narcd` - Main userspace daemon
- `narcd-ebpf` - eBPF program that runs in the kernel
- `narcd-common` - Shared types between userspace and eBPF (no_std compatible)

### Building

Build the entire project (includes compiling eBPF program):
```bash
cargo build --release
```

The build process:
1. `narcd/build.rs` runs cargo-in-cargo to build `narcd-ebpf` with `-Z build-std`
2. eBPF binary is compiled for BPF target and embedded into the `narcd` binary
3. Requires nightly toolchain with rust-src component and `bpf-linker` installed

### Running

Requires root privileges due to eBPF and network binding:
```bash
sudo cargo run
```

The `.cargo/config.toml` sets `runner = "sudo -E"` to handle this automatically.

### Testing

Standard cargo test commands:
```bash
cargo test
cargo test -p narcd          # Test specific package
cargo test -p narcd-common
```

## Architecture

### Two-Component System

1. **eBPF Component** (`narcd-ebpf/src/main.rs`)
   - XDP program attached to default network interface
   - Inspects packets at kernel level for TCP SYN packets (port scan indicators)
   - Writes flow data to `EVENTS` PerfEventArray map
   - Returns `XDP_PASS` to allow normal packet processing

2. **Userspace Component** (`narcd/src/main.rs`)
   - Loads and attaches eBPF program
   - Reads flow events from eBPF via PerfEventArray
   - Runs SSH and HTTP honeypot servers
   - Logs events to JSONL files

### Flow Collection & Port Scan Detection

Flow collection happens in `narcd/src/ebpf.rs`:

1. **Event Reading**: One async task per CPU core reads from PerfEventArray buffers
2. **Flow Aggregation**: `FlowCollector` aggregates flows by source IP and scan type
3. **Scan Detection**: Periodic sweeper (every 5s) identifies stale flows (>16s inactive)
4. **Threshold**: Port scans are logged when tracking shows activity to multiple unique ports

Key parameters in `narcd/src/ebpf.rs`:
- `FLOW_COLLECTOR_SWEEP_INTERVAL`: How often to check for stale flows
- `FLOW_STALE_THRESHOLD`: When to consider a flow complete
- `UNIQUE_PORTS_THRESHOLD`: Minimum unique ports to log as scan

### SSH Honeypot

Implementation in `narcd/src/listeners/ssh.rs`:
- Accepts SSH connections but rejects all authentication attempts
- Logs username, password/public key attempts with metadata
- Configurable via `narcd.toml` (listen address, port, timeouts, server ID)
- Auto-generates RSA host key if missing

### HTTP Honeypot

Implementation in `narcd/src/listeners/http.rs`:
- Accepts HTTP requests and returns configurable status code (default 403 Forbidden)
- Logs request method, path, headers, body, and authentication credentials
- Supports HTTP Basic Auth extraction (username/password from Authorization header)
- Configurable via `narcd.toml` (listen address, port, response status, body/header size limits)
- Uses hyper 1.x for HTTP/1.1 server implementation
- Per-connection timeouts prevent resource exhaustion

Event structure (`HttpRequest` in `narcd/src/events.rs`):
- `HttpAuthMethod` enum: None, Basic (username/password), or Other (non-basic auth)
- Logs common headers: User-Agent, Referer, Host, Content-Type
- Request body logged with configurable size limit (default 4KB)
- `body_truncated` flag indicates if body exceeded size limit

### Event Logging

Generic `EventLogger` trait in `narcd/src/logger.rs`:
- `FileLogger` implementation writes JSONL to disk
- Async channel-based (2048 buffer) to avoid blocking
- Three log files: `scan.log` (port scans), `ssh.log` (SSH attempts), `http.log` (HTTP requests)

### Metadata System

`narcd/src/metadata.rs` resolves instance metadata:
- Fetches AWS EC2 metadata via IMDS client
- Determines local IP address
- Metadata is included in all logged events for context

### Configuration

Config file loaded from:
1. `/etc/narcd/narcd.toml` (production)
2. `./narcd.toml` (development)

Structure defined in `narcd/src/config.rs` with sub-configs for listeners and logging.

## Development Workflow

### Making Changes to eBPF Code

When modifying `narcd-ebpf/src/main.rs`:
1. Changes to packet parsing or flow detection logic
2. Rebuild triggers recompilation via build.rs
3. New eBPF binary is embedded into userspace binary
4. Test with `sudo cargo run` to load new eBPF program

### Shared Types

`narcd-common/src/lib.rs` defines types used across kernel/userspace boundary:
- Must be `no_std` compatible
- Cannot use types with dynamic allocation
- Uses conditional compilation with feature flags (`std`, `serde`, `user`)
- Memory layout must be identical between kernel and userspace

### Adding New Flow Types

1. Add variant to `FlowType` enum in `narcd-common/src/lib.rs`
2. Update eBPF detection logic in `narcd-ebpf/src/main.rs`
3. Consider impact on flow aggregation in `narcd/src/ebpf.rs`

### Adding New Listeners

Follow the pattern in `narcd/src/listeners/`:
1. Create new module with config struct and start function
2. Add to `ListenersConfig` in `narcd/src/listeners/mod.rs`
3. Define event type in `narcd/src/events.rs`
4. Spawn listener in `narcd/src/main.rs`

## Deployment

AWS CodeDeploy/CodeBuild setup:
- `buildspec.yml`: Builds release binary with required toolchains
- `appspec.yml`: Deploys to `/opt/narcd/bin`, installs systemd service
- `service/narcd.service`: systemd unit file
- `codedeploy/`: Lifecycle hooks for deployment

## Important Notes

- eBPF programs require kernel verifier approval - avoid unbounded loops, use helpers correctly
- Flow struct must maintain same memory layout between eBPF and userspace
- PerfEventArray buffers can overflow under high traffic - monitor lost events warnings
- Cargo workspace uses edition 2024 and custom aya dependency from git
