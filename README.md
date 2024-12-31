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

# Run (requires root privileges)
sudo go run main.go
```

## Requirements

- Go 1.16+
- Root/Administrator privileges
- libpcap (install via `brew install libpcap` on macOS)

## Usage

After building the tool, you can run it with the following command:

```bash
sudo go run main.go -interface <network-interface> -target <target-ip-or-domain> -port <target-port> -numPackets <number-of-packets>
```

Replace `<network-interface>`, `<target-ip-or-domain>`, `<target-port>`, and `<number-of-packets>` with the appropriate values.

Example:

```bash
sudo go run main.go -interface en0 -target example.com -port 80 -numPackets 1000
```

