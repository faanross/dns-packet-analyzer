package visualizer

import (
	"fmt"
	"github.com/fatih/color"
	"strings"
)

const (
	// bytesPerRow defines how many bytes to show per line in the hex dump.
	bytesPerRow = 16
)

// VisualizePacket prints a DNS packet in a user-friendly hex and ASCII format.
func VisualizePacket(packet []byte) {

	color.Cyan("---------------------->>> DNS PACKET VISUALIZATION <<<----------------------")

	if len(packet) == 0 {
		color.Red("ERROR: Empty packet")
		return
	}

	// strings.Builder is built for efficiently building a string from multiple pieces.
	var hexBuilder, asciiBuilder strings.Builder

	for i, b := range packet {

		// Build our HEX Output
		hexBuilder.WriteString(fmt.Sprintf("%02X ", b))

		// Build our ASCII Output

		// If the character is printable, print it. Otherwise, use a dot.
		if b >= 32 && b <= 126 {
			asciiBuilder.WriteByte(b)
		} else {
			asciiBuilder.WriteByte('.')
		}

		// Check if we've reached the end of a row OR the end of the packet.
		if (i+1)%bytesPerRow == 0 || i == len(packet)-1 {

			// Print the offset (address) of the current row.
			color.New(color.FgYellow).Printf("0x%04X | ", i-((i)%bytesPerRow))

			// Print the hex part, padded to a fixed width for alignment.
			hexStr := hexBuilder.String()
			fmt.Printf("%-48s", hexStr) // 16 bytes * 3 chars/byte (XX ) = 48

			// Print the ASCII part.

			color.New(color.FgMagenta).Printf("| %s\n", asciiBuilder.String())

			// Reset the builders for the next row.
			hexBuilder.Reset()
			asciiBuilder.Reset()
		}

	}

	color.Cyan(">>>>--------------------------------------------------------------------<<<<")
}
