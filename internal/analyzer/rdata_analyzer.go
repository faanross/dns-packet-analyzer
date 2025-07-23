package analyzer

import (
	"encoding/hex"
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
	// Only analyze TXT records
	txtRecord, ok := rr.(*dns.TXT)
	if !ok {
		return nil
	}

	// Combine all TXT strings
	var combinedData string
	for _, txt := range txtRecord.Txt {
		combinedData += txt
	}

	analysis := &RDATAAnalysis{
		HexDetected:    detectHex(combinedData),
		Base64Detected: detectBase64(combinedData),
		Capacity:       calculateCapacity(txtRecord),
	}

	return analysis
}

// detectHex checks if the string contains hex-encoded data
func detectHex(data string) bool {
	// Remove common separators
	cleaned := strings.ReplaceAll(data, " ", "")
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Check if it's valid hex and has significant length
	if len(cleaned) < 32 { // Minimum 16 bytes of hex data
		return false
	}

	_, err := hex.DecodeString(cleaned)
	return err == nil && isHighEntropyHex(cleaned)
}

// detectBase64 checks if the string contains base64-encoded data
func detectBase64(data string) bool {
	// Base64 regex pattern
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

	// Check minimum length for suspicious base64
	if len(data) < 32 {
		return false
	}

	// Remove whitespace
	cleaned := strings.ReplaceAll(data, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	return base64Pattern.MatchString(cleaned) && isHighEntropyBase64(cleaned)
}

// isHighEntropyHex checks if hex string has high entropy (likely encoded data)
func isHighEntropyHex(data string) bool {
	// Simple entropy check - count unique characters
	charCount := make(map[rune]int)
	for _, ch := range strings.ToLower(data) {
		charCount[ch]++
	}

	// If we have good distribution across hex chars, it's likely encoded data
	return len(charCount) >= 10 // At least 10 different hex characters
}

// isHighEntropyBase64 checks if base64 string has high entropy
func isHighEntropyBase64(data string) bool {
	// Count unique characters
	charCount := make(map[rune]int)
	for _, ch := range data {
		charCount[ch]++
	}

	// High entropy base64 should use many different characters
	return len(charCount) >= 20
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
