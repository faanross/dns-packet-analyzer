package models

import "github.com/miekg/dns"

// DNSPacket is used for analyzer's initial classification of dns packets in pcap
type DNSPacket struct {
	SrcIP   string
	DstIP   string
	Type    string // "Request" or "Response"
	RawData []byte
	Msg     *dns.Msg // Parsed miekg msg object
	ZValue  uint8
}
