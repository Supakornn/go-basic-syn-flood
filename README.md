# SYN Flood Testing Tool

A simple network testing tool for simulating SYN flood attacks, written in Go using the gopacket library.

⚠️ **WARNING: Educational purposes only. Unauthorized usage against targets is illegal.**

## Quick Start

```bash
# Clone repository
git clone https://github.com/Supakornn/syn-flood
cd syn-flood

# Install dependencies
go mod tidy

# Build
go build
```

## Requirements

- Go 1.16+
- Root/Administrator privileges
- libpcap (install via `brew install libpcap` on macOS)

## Usage

```bash
sudo ./syn-flood -interface <network-interface> -target <target-ip-or-domain> -port <target-port> -numPackets <number-of-packets>
```

Example:

```bash
sudo ./syn-flood -interface en0 -target example.com -port 80 -numPackets 1000
```
