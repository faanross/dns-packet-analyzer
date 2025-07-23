package crafter

import (
	"encoding/binary"
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/models"
)

// ApplyManualOverride directly manipulates the byte slice of a packed DNS message.
func ApplyManualOverride(packedMsg []byte, header models.Header) error {
	// The DNS header is 12 bytes long. If the packet is shorter, something is wrong.
	if len(packedMsg) < 12 {
		return fmt.Errorf("packed message is too short to be a valid DNS packet (%d bytes)", len(packedMsg))
	}

	// The flags are in the 3rd and 4th bytes of the header (indices 2 and 3).
	// We read them as a single 16-bit integer in Big Endian (network) byte order.
	flags := binary.BigEndian.Uint16(packedMsg[2:4])

	// --- Manipulate the Z flag ---

	// 1. Create a "clearing mask" to set the 3 Z bits to 0.
	// The Z bits are bits 4, 5, and 6 from the left of this field.
	// In a 16-bit number, this corresponds to bits 9, 8, and 7.
	// Mask in binary: 1111 1111 1000 1111
	// Mask in hex:   0x  F    F    8    F
	const zClearMask uint16 = 0xFF8F
	flags &= zClearMask

	// 2. Prepare our desired Z value. It's a 3-bit value (0-7).
	// We must shift it left by 4 bits to align it with the RCODE field.
	zValue := uint16(header.Z) << 4

	// 3. Use a bitwise OR to apply our shifted Z value to the cleared flags.
	flags |= zValue

	// --- Write the modified flags back into the byte slice ---
	binary.BigEndian.PutUint16(packedMsg[2:4], flags)

	//fmt.Printf("\n>>> Manually set Z flag to %d. New flags value: 0x%04X\n", header.Z, flags)

	return nil
}
