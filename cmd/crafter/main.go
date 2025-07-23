package main

import (
	"errors"
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/crafter"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"github.com/faanross/dns-packet-analyzer/internal/utils"
	"github.com/faanross/dns-packet-analyzer/internal/visualizer"
	"gopkg.in/yaml.v3"
	"os"
)

// assume go run from root, otherwise change path
// if you prefer to statically compile to a single binary
// create a constructor with hardcoded values and bypass yaml
var pathToYamlFile = "./cmd/crafter/config.yaml"

func main() {
	// (1) read yaml-file from disk

	yamlFile, err := os.ReadFile(pathToYamlFile)
	if err != nil {
		fmt.Printf("Error reading YAML file: %v\n", err)
		return
	}

	// (2) DNS request struct + unmarshall

	var dnsRequest models.DNSRequest
	err = yaml.Unmarshal(yamlFile, &dnsRequest)
	if err != nil {
		fmt.Printf("Error unmarshalling YAML file: %v\n", err)
		return
	}

	// (3) validate request fields

	if err := utils.ValidateRequest(&dnsRequest); err != nil {
		// Use a type assertion to check if it's the specific type we're looking for.
		var validationErrs utils.ValidationErrors
		if errors.As(err, &validationErrs) {
			fmt.Println("Configuration is invalid. Errors:")
			for _, validationErr := range validationErrs {
				fmt.Printf("  - %s\n", validationErr)
			}
		}
		return
	} else {
		fmt.Printf("✅ DNS request configuration is valid!\n\n")
	}

	// (4) build dns.Msg (miekg/dns library object)

	dnsMsg, err := crafter.BuildDNSRequest(dnsRequest)
	if err != nil {
		fmt.Printf("Error building DNS request using miekg: %v\n", err)
		return
	}

	// (5) pack the dnsMsg to convert to byte slice
	// this is needed to manipulate Z-value manually

	packedMsg, err := dnsMsg.Pack()
	if err != nil {
		fmt.Printf("Error packing message: %v\n", err)
		return
	}

	// (6) now we can apply our manual override for the Z flag

	err = crafter.ApplyManualOverride(packedMsg, dnsRequest.Header)
	if err != nil {
		fmt.Printf("Error applying manual overrides: %v\n", err)
		return
	}

	// (7) visualize our outgoing (request) packet to terminal
	visualizer.VisualizePacket(packedMsg)

}
