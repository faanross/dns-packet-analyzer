package network

import (
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"net"
	"time"
)

// SendAndReceivePacket sends a raw DNS packet to a
// resolver over UDP and handles the response.

func SendAndReceivePacket(packet []byte, resolver models.Resolver) ([]byte, error) {

	// Combine IP and Port
	address := fmt.Sprintf("%s:%d", resolver.IP, resolver.Port)

	// Resolve string address into a UDP address object
	rAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Establish UDP connection
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}

	defer conn.Close()

	fmt.Printf("\n🚀 Sending packet to %s\n", address)

	// Send packet

	_, err = conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %w", err)
	}
	fmt.Println("✅  Packet sent successfully.")

	// Set a read deadline (5 seconds)
	deadline := time.Now().Add(5 * time.Second)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Buffer to hold the response
	// DNS responses can be up to 512 bytes for standard UDP
	// Will double just in case of extensions (EDNS)

	response := make([]byte, 1024)

	// Read response, note this is a blocking call
	// until data is received or the deadline is hit
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	fmt.Printf("🫴 Received %d bytes.\n", n)

	// Return only the part of the buffer that contains data
	return response[:n], nil
}
