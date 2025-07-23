package utils

import (
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"net"
	"strings"
)

// ValidationErrors is a custom error type that holds a slice of validation errors.
type ValidationErrors []error

// Error implements the error interface for ValidationErrors.
// It joins all the underlying errors into a single string.
func (v ValidationErrors) Error() string {
	var b strings.Builder

	b.WriteString("validation failed with the following errors:\n")
	for _, err := range v {
		b.WriteString(fmt.Sprintf("- %s\n", err))
	}
	return b.String()
}

func ValidateRequest(dnsRequest *models.DNSRequest) error {

	var validateErrs ValidationErrors

	// HEADER SECTION VALIDATION

	// make sure Header.OpCode appears in our OpCodeMap
	if _, ok := models.OpCodeMap[dnsRequest.Header.OpCode]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid opcode: %s", dnsRequest.Header.OpCode))
	}

	// make sure Header.Z is not >7 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.Z > 7 {
		validateErrs = append(validateErrs, fmt.Errorf("Z flag must be between 0 and 7, but got %d", dnsRequest.Header.Z))
	}

	// make sure Header.RCode is not >15 (note uint8 already ensure it's >=0)
	if dnsRequest.Header.RCode > 15 {
		validateErrs = append(validateErrs, fmt.Errorf("RCode must be between 0 and 15, but got %d", dnsRequest.Header.RCode))
	}

	// QUESTION SECTION VALIDATION
	// make sure Question.Type appears in our QTypeMap
	if _, ok := models.QTypeMap[dnsRequest.Question.Type]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question type: %s", dnsRequest.Question.Type))
	}

	// make sure Question.Class appears in our QClassMap
	if _, ok := models.QClassMap[dnsRequest.Question.Class]; !ok {
		validateErrs = append(validateErrs, fmt.Errorf("invalid question class: %s", dnsRequest.Question.Class))
	}

	// RESOLVER SECTION VALIDATION

	// if UseSystemDefaults if false
	if !dnsRequest.Resolver.UseSystemDefaults {
		// Resolver.IP has to be a valid IP
		if net.ParseIP(dnsRequest.Resolver.IP) == nil {
			validateErrs = append(validateErrs, fmt.Errorf("resolver IP is not a valid IP address: %s", dnsRequest.Resolver.IP))
		}

		// Resolver.Port has to be a valid Port
		if dnsRequest.Resolver.Port < 1 || dnsRequest.Resolver.Port > 65535 {
			validateErrs = append(validateErrs, fmt.Errorf("resolver port is not a valid port number: %d", dnsRequest.Resolver.Port))
		}
	}

	if len(validateErrs) > 0 {
		return validateErrs
	}

	return nil
}
