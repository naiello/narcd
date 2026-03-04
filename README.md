# narcd

`narcd` is a network threat monitoring daemon that combines eBPF-based packet inspection with SSH and HTTP honeypot capabilities. It is designed to run on Linux systems (particularly AWS EC2 instances) and logs all interactions to JSONL files for downstream analysis.

## Features

### Port Scan Detection

An XDP eBPF program is attached to the default network interface and inspects TCP SYN packets at the kernel level. The userspace daemon aggregates flows by source IP and logs a scan event when traffic reaches multiple unique destination ports within a time window.

### SSH Honeypot

Accepts SSH connections but rejects all authentication attempts, logging each one. Captures:
- Username
- Password attempts (with strength statistics — Shannon entropy and zxcvbn guess count)
- Public key attempts (algorithm, fingerprint, comment)

### HTTP Honeypot

Accepts HTTP/1.1 requests and returns a configurable response (default: 403 Forbidden). Logs:
- Method, path, and common headers (User-Agent, Referer, Host, Content-Type)
- Request body (up to a configurable size limit)
- HTTP Basic Auth credentials

Multiple listen ports are supported.

## Enrichments

Each logged event is enriched with additional context at capture time:

| Enrichment | Description |
|---|---|
| **ASN lookup** | Autonomous system number, description, and country for the source IP |
| **GeoIP** | Country, region, city, coordinates, and timezone for the source IP |
| **Reverse DNS** | Hostname resolved from the source IP |
| **Instance metadata** | AWS EC2 instance ID, region, and AZ (via IMDS); falls back to local IP |

### Observable Extraction (HTTP)

HTTP request bodies and paths are scanned for embedded indicators:

- **IP addresses** (IPv4 and IPv6)
- **URLs** (http, https, ftp schemes)

## Output

Events are written to JSONL log files:

| File | Contents |
|---|---|
| `scan.log` | Port scan events |
| `ssh.log` | SSH authentication attempts |
| `http.log` | HTTP requests |

## Configuration

Configuration is loaded from `/etc/narcd/narcd.toml` (production) or `./narcd.toml` (development). Options include listener addresses and ports, response codes, body size limits, and timeouts.

## Building

```bash
cargo build --release
```

Requires a nightly Rust toolchain with `rust-src` and `bpf-linker` installed. Running requires root:

```bash
sudo cargo run
```
