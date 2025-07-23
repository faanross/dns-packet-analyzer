package models

import "github.com/miekg/dns"

// DNSPacket is used for analyzer's initial classification of dns packets in pcap
type DNSPacket struct {
	SrcIP         string
	DstIP         string
	Type          string // "Request" or "Response"
	RawData       []byte
	Msg           *dns.Msg // Parsed miekg msg object
	ZValue        uint8
	RecordType    string // DNS record type (A, MX, CNAME, etc.)
	RDATAAnalysis *RDATAAnalysis
}

// DNSRequest will hold the complete agent-side
// configuration parsed from configs/request.yaml
// It embeds 3 other structs, defined below
type DNSRequest struct {
	Header   Header   `yaml:"header"`
	Question Question `yaml:"question"`
	Resolver Resolver `yaml:"resolver"`
}

// Header represents the DNS header section.
type Header struct {
	// Query ID (16 bits): A random ID to match requests with replies.
	ID uint16 `yaml:"id"`

	// QR (1 bit): false means query, true means response
	QR bool `yaml:"qr"`

	// OpCode (4 bits): Specifies the kind of query.
	OpCode string `yaml:"opcode"`

	// Flags (1 bit each): These boolean flags control the behavior of the DNS query.
	Authoritative      bool `yaml:"authoritative"`       // AA
	Truncated          bool `yaml:"truncated"`           // TC
	RecursionDesired   bool `yaml:"recursion_desired"`   // RD
	RecursionAvailable bool `yaml:"recursion_available"` // RA

	// Z (3 bits): Reserved bits. Per RFC 1035, this "must be zero".
	// We expose it to allow for non-standard values (inspired by DNS sandwich).
	Z uint8 `yaml:"z"`

	// RCode (4 bits): Response code. We use uint8 (0-15) to allow setting
	// any value, including standard codes and reserved ones (11 - 15).
	RCode uint8 `yaml:"rcode"`
}

// Question represents the question section of a DNS query.
type Question struct {
	// Name: The domain name being queried (e.g., "www.vuilhond.com").
	Name string `yaml:"name"`

	// Type: The type of record being requested (e.g., "A", "AAAA", "MX").
	Type string `yaml:"type"`

	// Class: The protocol class, almost always "IN" for internet.
	Class string `yaml:"class"`
}

// Resolver holds the information about the DNS resolver we're sending the packet to.
type Resolver struct {
	// UseSystemDefaults, if true, will ignore the IP and Port fields and instead
	// discover and use the host operating system's default DNS resolver.
	UseSystemDefaults bool `yaml:"use_system_defaults"`

	// if UseSystemDefaults is false we can manually set the server/resolver here
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

// RDATAAnalysis is for info related to TXT response RDATA analysis
type RDATAAnalysis struct {
	HexDetected    bool
	Base64Detected bool
	Capacity       float64
}
