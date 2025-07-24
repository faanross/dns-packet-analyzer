package analyzer

import (
	"fmt"
	"github.com/miekg/dns"
	"regexp"
	"strings"
)

// RDATAAnalysis holds the analysis results for RDATA content
type RDATAAnalysis struct {
	HexDetected    bool
	Base64Detected bool
	Capacity       float64
}

// AnalyzeRDATA analyzes the RDATA content of DNS records
func AnalyzeRDATA(rr dns.RR) *RDATAAnalysis {
	// Debug print
	fmt.Printf("DEBUG AnalyzeRDATA: Record type: %T\n", rr)

	// Only analyze TXT records
	txtRecord, ok := rr.(*dns.TXT)
	if !ok {
		fmt.Printf("DEBUG: Not a TXT record, skipping\n")
		return nil
	}

	// Combine all TXT strings
	var combinedData string
	for _, txt := range txtRecord.Txt {
		combinedData += txt
	}

	fmt.Printf("DEBUG: TXT data: %s (length: %d)\n", combinedData, len(combinedData))

	analysis := &RDATAAnalysis{
		HexDetected:    detectHex(combinedData),
		Base64Detected: detectBase64(combinedData),
		Capacity:       calculateCapacity(txtRecord),
	}

	return analysis
}

// detectHex checks if the string looks like hex-encoded data
func detectHex(data string) bool {
	// Remove common separators
	cleaned := strings.ReplaceAll(data, " ", "")
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Check minimum length for suspicious hex
	if len(cleaned) < 32 { // Minimum 16 bytes of hex data
		return false
	}

	// Check if all characters are valid hex characters
	hexPattern := regexp.MustCompile("^[0-9a-fA-F]+$")
	if !hexPattern.MatchString(cleaned) {
		return false
	}

	// Additional check: hex strings typically have even length
	if len(cleaned)%2 != 0 {
		return false
	}

	// If it passes all checks, it's likely hex
	return true
}

// detectBase64 checks if the string looks like base64-encoded data
func detectBase64(data string) bool {
	// Remove whitespace
	cleaned := strings.ReplaceAll(data, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	// Check minimum length
	if len(cleaned) < 32 {
		return false
	}

	// Base64 pattern - must be only valid base64 chars
	base64Pattern := regexp.MustCompile("^[A-Za-z0-9+/]+=*$")
	if !base64Pattern.MatchString(cleaned) {
		return false
	}

	// Check if padding is correct (if present)
	if strings.Contains(cleaned, "=") {
		// Padding should only be at the end
		if !strings.HasSuffix(cleaned, "=") && !strings.HasSuffix(cleaned, "==") {
			return false
		}
	}

	// Length check - base64 encoded data length is always multiple of 4
	if len(cleaned)%4 != 0 {
		return false
	}

	return true
}

// calculateCapacity calculates the percentage of TXT record capacity used
func calculateCapacity(txt *dns.TXT) float64 {
	totalLength := 0
	for _, str := range txt.Txt {
		totalLength += len(str)
	}

	// TXT records can have multiple strings of 255 chars each
	// But typical single TXT record capacity is 255 bytes
	maxCapacity := 255.0
	if len(txt.Txt) > 1 {
		maxCapacity = float64(len(txt.Txt)) * 255.0
	}

	return (float64(totalLength) / maxCapacity) * 100.0
}
