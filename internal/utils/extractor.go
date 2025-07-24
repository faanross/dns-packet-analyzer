package utils

import (
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/analyzer"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

// ExtractDNSPackets is used to extract DNS packets from a pcap for our analyzer
func ExtractDNSPackets(pcapFile string) ([]models.DNSPacket, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var dnsPackets []models.DNSPacket
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dnsLayerContent := dnsLayer.LayerContents()
			dnsPacket := dnsLayer.(*layers.DNS)

			var srcIP, dstIP string
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip := ipLayer.(*layers.IPv6)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}

			pktType := "Request"
			if dnsPacket.QR {
				pktType = "Response"
			}

			// Extract actual Z value from raw packet
			var zValue uint8
			if len(dnsLayerContent) >= 4 {
				// Z field is bits 9-11 of the flags (second 16-bit word)
				// Flags are in bytes 2-3 of the DNS header
				flags := uint16(dnsLayerContent[2])<<8 | uint16(dnsLayerContent[3])
				// Z is bits 6-4 of the second byte (when counting from MSB)
				// Which is bits 9-11 of the 16-bit flags field
				zValue = uint8((flags >> 4) & 0x07)
			}

			// Pre-parse the DNS message
			msg := new(dns.Msg)
			var recordType string = "Unknown"

			if err := msg.Unpack(dnsLayerContent); err == nil {
				// Extract record type based on packet type
				if pktType == "Request" {
					// For requests, get the type from the question section
					if len(msg.Question) > 0 {
						recordType = dns.TypeToString[msg.Question[0].Qtype]
					}
				} else {
					// For responses, get the type from the first answer record
					// If no answer records, fall back to question section
					if len(msg.Answer) > 0 {
						recordType = dns.TypeToString[msg.Answer[0].Header().Rrtype]
					} else if len(msg.Question) > 0 {
						recordType = dns.TypeToString[msg.Question[0].Qtype]
					}
				}

				// Do RDATA analysis on response TXT sections
				var rdataAnalysis *models.RDATAAnalysis

				if pktType == "Response" && len(msg.Answer) > 0 {
					// Debug: Print what we're analyzing
					fmt.Printf("DEBUG: Analyzing response with %d answers\n", len(msg.Answer))

					// Analyze first TXT record in answers
					for i, answer := range msg.Answer {
						fmt.Printf("DEBUG: Answer %d type: %s\n", i, dns.TypeToString[answer.Header().Rrtype])

						if analysis := analyzer.AnalyzeRDATA(answer); analysis != nil {
							fmt.Printf("DEBUG: Analysis found! Hex: %v, Base64: %v, Capacity: %.2f%%\n",
								analysis.HexDetected, analysis.Base64Detected, analysis.Capacity)

							rdataAnalysis = &models.RDATAAnalysis{
								HexDetected:    analysis.HexDetected,
								Base64Detected: analysis.Base64Detected,
								Capacity:       analysis.Capacity,
							}
							break // Analyze only the first TXT record
						}
					}

					if rdataAnalysis == nil {
						fmt.Printf("DEBUG: No TXT records found for analysis\n")
					}
				}

				dnsPackets = append(dnsPackets, models.DNSPacket{
					SrcIP:         srcIP,
					DstIP:         dstIP,
					Type:          pktType,
					RecordType:    recordType,
					RawData:       dnsLayerContent,
					Msg:           msg,
					ZValue:        zValue,
					RDATAAnalysis: rdataAnalysis,
				})
			}
		}
	}

	return dnsPackets, nil
}
