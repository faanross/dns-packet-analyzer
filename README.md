# DNS Packet Analyzer

A Go-based toolkit for DNS-based covert channel emulation packet analysis and crafting. 
Designed for network security researchers, threat hunters, and DNS protocol enthusiasts. 
This tool provides deep inspection capabilities for DNS packets and allows crafting of custom DNS packets with 
full control over all fields, including rarely-examined ones like the Z (reserved) bits.

## 🎯 Key Features

- **Deep Packet Analysis**: Examine every field of DNS packets, including often-overlooked reserved bits
- **Custom Packet Crafting**: Create DNS packets with complete control over all header fields via YAML configuration
- **Anomaly Detection**: Identify unusual DNS packet characteristics that might indicate malicious activity
- **Interactive TUI**: Terminal-based user interface for easy navigation through captured packets
- **Visual Packet Inspection**: Hex and ASCII visualization of raw packet data
- **Cross-Platform**: Works on Windows, macOS, and Linux

## 🚨 Security Use Cases

This tool is particularly valuable for:
- **Threat Hunting**: Detect DNS-based covert channels and data exfiltration attempts
- **Security Research**: Analyze DNS tunneling techniques and protocol abuse
- **Anomaly Detection**: Identify non-standard DNS implementations that might bypass security controls
- **DNS Firewall Testing**: Validate security controls against crafted DNS packets

### Example: DNS Sandwich Detection
The tool can detect unusual Z-bit values (reserved bits that should be zero per RFC 1035) which are used by advanced threats like DNS Sandwich for covert communication channels.

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Components](#components)
    - [Analyzer](#analyzer)
    - [Crafter](#crafter)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Building from Source](#building-from-source)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## 🔧 Installation

### Prerequisites

- Go 1.23.3 or higher
- libpcap (for packet capture analysis)
    - **macOS**: `brew install libpcap`
    - **Ubuntu/Debian**: `sudo apt-get install libpcap-dev`
    - **RHEL/CentOS**: `sudo yum install libpcap-devel`
    - **Windows**: Install [WinPcap](https://www.winpcap.org/) or [Npcap](https://nmap.org/npcap/)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/faanross/dns-packet-analyzer.git
cd dns-packet-analyzer

# Install dependencies
go mod download
go mod tidy

# Build the tools
go build -o dns-analyzer ./cmd/analyzer
go build -o dns-crafter ./cmd/crafter
```

## 🚀 Quick Start

### Analyzing DNS Packets

```bash
# Analyze a PCAP file containing DNS traffic
./dns-analyzer -pcap sample.pcap
```

### Crafting DNS Packets

```bash
# Edit the configuration file
vim cmd/crafter/config.yaml

# Run the crafter
go run cmd/crafter/main.go
```

## 🔍 Components

### Analyzer

The analyzer component provides deep inspection of DNS packets from PCAP files with an interactive terminal UI.

#### Features:
- **Packet List View**: Browse through all DNS packets with source/destination IPs and packet types
- **Detailed Packet View**: Examine every field of selected packets including:
    - Complete DNS header analysis
    - Question section details
    - Answer/Authority/Additional sections
    - Raw hex dump visualization
- **Anomaly Highlighting**: Automatic detection and warning for non-standard field values

#### Usage:

```bash
./dns-analyzer -pcap <path-to-pcap-file>
```

#### Navigation:
- `↑/↓`: Navigate through packet list
- `Enter`: View detailed packet information
- `q`: Quit or return to list view
- `ESC`: Exit application

#### Example Output:
```
╔══════════════════════════╗
║    DNS PACKET DETAILS    ║
╚══════════════════════════╝

📦 PACKET INFORMATION
   Source: 192.168.1.100 → Destination: 8.8.8.8
   Type: Query | Size: 43 bytes

🏷️ DNS HEADER
├──────────────────────────────────────────
├ ID: 54321
├ QR: 0 (Query)
├ Opcode: 0 (QUERY)
├ AA: 0 (Authoritative Answer: No)
├ TC: 0 (Truncated: No)
├ RD: 1 (Recursion Desired: Yes)
├ RA: 0 (Recursion Available: No)
├ Z: 6 (Reserved - should be 0)
├ ⚠️  WARNING: Non-zero Z value detected!
├ RCODE: 0 (NOERROR)
└──────────────────────────────────────────
```

### Crafter

The crafter component allows creation of custom DNS packets with precise control over every field through YAML configuration.

#### Features:
- **Full Header Control**: Set any combination of DNS flags and fields
- **Z-Bit Manipulation**: Override reserved bits for testing security controls
- **System Resolver Detection**: Automatically use system DNS settings or specify custom resolvers
- **Packet Visualization**: See the crafted packet in hex/ASCII format when sending

#### Configuration File Structure:

```yaml
resolver:
  # Use system DNS resolver or specify custom
  use_system_defaults: false
  ip: "1.1.1.1"
  port: 53

header:
  # 16-bit identifier (0 = random)
  id: 0
  
  # Query/Response flag
  qr: false
  
  # Operation code
  opcode: "QUERY"
  
  # DNS flags
  authoritative: false
  truncated: false
  recursion_desired: true
  recursion_available: false
  
  # Z field (reserved bits) - normally must be 0
  # Setting non-zero values for security testing
  z: 6
  
  # Response code (0-15)
  rcode: 0

question:
  # Domain to query (FQDN with trailing dot)
  name: "www.example.com."
  
  # Record type (A, AAAA, MX, TXT, etc.)
  type: "A"
  
  # Query class (usually IN for Internet)
  class: "IN"
```

## 📚 Usage Examples

### Example 1: Detecting DNS Tunneling

```bash
# Capture suspicious DNS traffic
sudo tcpdump -i eth0 -w suspicious.pcap 'port 53'

# Analyze with dns-analyzer
./dns-analyzer -pcap suspicious.pcap

# Look for:
# - Unusually large DNS queries
# - Non-zero Z bits
# - Strange query patterns
# - Uncommon record types
```

### Example 2: Testing DNS Firewall

```yaml
# Create test packet with non-standard Z value
# Edit config.yaml:
header:
  z: 7  # Maximum Z value (3 bits = 0-7)
  recursion_desired: true
  
question:
  name: "test.malicious.com."
  type: "TXT"
```

```bash
# Generate the packet
./dns-crafter

# Verify if your DNS firewall detects the anomaly
```

### Example 3: Analyzing DNS Covert Channels

```bash
# Look for packets with unusual characteristics
./dns-analyzer -pcap covert_channel.pcap

# Check for:
# - Non-zero Z values (DNS Sandwich indicator)
# - Unusual RCODE values in queries
# - Patterns in DNS IDs
# - Encoded data in subdomain labels
```

## ⚙️ Configuration

### Supported DNS Record Types

The crafter supports all standard DNS record types including:
- Common: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR
- Security: DNSKEY, DS, RRSIG, NSEC, NSEC3, TLSA
- Service: SRV, NAPTR, CAA, SVCB, HTTPS
- Special: OPT, ANY, AXFR, IXFR

### Supported OpCodes

- QUERY (standard query)
- IQUERY (inverse query)
- STATUS (server status request)
- NOTIFY (zone change notification)
- UPDATE (dynamic update)

### RCODE Values

Supports all 16 possible RCODE values (0-15):
- 0: NOERROR
- 1: FORMERR
- 2: SERVFAIL
- 3: NXDOMAIN
- 4: NOTIMP
- 5: REFUSED
- 6-15: Various extended codes

## 🏗️ Architecture

```
dns-packet-analyzer/
├── cmd/
│   ├── analyzer/         # Packet analyzer application
│   │   ├── main.go      # Entry point
│   │   └── app.go       # TUI application logic
│   └── crafter/         # Packet crafter application
│       ├── main.go      # Entry point
│       └── config.yaml  # Example configuration
├── internal/
│   ├── models/          # Data structures
│   │   ├── models.go    # Core types
│   │   └── maps.go      # DNS constant mappings
│   ├── utils/           # Utility functions
│   │   ├── extractor.go # PCAP extraction
│   │   ├── validate.go  # Input validation
│   │   └── resolver.go  # System resolver detection
│   ├── crafter/         # Packet crafting logic
│   │   ├── craft_request.go    # DNS message builder
│   │   └── manual_override.go  # Z-bit manipulation
│   └── visualizer/      # Packet visualization
│       └── visualizer.go # Hex/ASCII display
└── go.mod              # Go module definition
```

### Key Design Decisions

1. **Direct Byte Manipulation**: The Z-bit field cannot be set using standard DNS libraries, so we manipulate the packed message bytes directly using bitwise operations.
2. **Terminal UI**: Uses `termbox-go` for cross-platform terminal interface
3. **Extensive Validation**: All inputs are validated before packet crafting to prevent errors
4. **Modular Architecture**: Clear separation between analysis and crafting components

## 🔧 Building from Source

### Development Build

```bash
# Run analyzer from source
go run cmd/analyzer/main.go -pcap sample.pcap

# Run crafter from source
go run cmd/crafter/main.go
```

### Production Build

```bash
# Build with optimizations
go build -ldflags="-s -w" -o dns-analyzer ./cmd/analyzer
go build -ldflags="-s -w" -o dns-crafter ./cmd/crafter

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build -o dns-analyzer-linux ./cmd/analyzer
GOOS=darwin GOARCH=amd64 go build -o dns-analyzer-macos ./cmd/analyzer
GOOS=windows GOARCH=amd64 go build -o dns-analyzer.exe ./cmd/analyzer
```


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Guidelines

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## 📝 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- [miekg/dns](https://github.com/miekg/dns) - DNS library for Go
- [google/gopacket](https://github.com/google/gopacket) - Packet processing library
- [nsf/termbox-go](https://github.com/nsf/termbox-go) - Terminal UI library
- [fatih/color](https://github.com/fatih/color) - Terminal color output

## ⚠️ Disclaimer

This tool is intended for legitimate security research, network diagnostics, and educational purposes only. Users are responsible for complying with applicable laws and regulations. I am not responsible for any misuse of this software.

## 📧 Contact

- Repository: [https://github.com/faanross/dns-packet-analyzer](https://github.com/faanross/dns-packet-analyzer)
- Issues: [https://github.com/faanross/dns-packet-analyzer/issues](https://github.com/faanross/dns-packet-analyzer/issues)
- [Personal Homepage](https://www.faanross.com)

Live Long + Prosper,
Faan

---
