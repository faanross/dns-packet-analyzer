package main

import (
	"errors"
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/crafter"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"github.com/faanross/dns-packet-analyzer/internal/network"
	"github.com/faanross/dns-packet-analyzer/internal/utils"
	"github.com/faanross/dns-packet-analyzer/internal/visualizer"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"os"
)

// assume go run from root, otherwise change path
// if you prefer to statically compile to a self-contained binary
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

	// (8) determine the final resolver to use based on the YAML config pref
	finalResolver, err := utils.DetermineResolver(dnsRequest.Resolver)
	if err != nil {
		fmt.Printf("Error determining resolver: %v\n", err)
		return
	}

	// (9) send request + receive response
	responseBytes, err := network.SendAndReceivePacket(packedMsg, finalResolver)
	if err != nil {
		fmt.Printf("\nError during network communication: %v\n", err)
		return
	}

	// (10) process and display response
	color.Green("\n--- DNS Server Response ---")
	var responseMsg dns.Msg
	err = responseMsg.Unpack(responseBytes)
	if err != nil {
		fmt.Printf("Error unpacking response packet: %v\n", err)
		// Even if unpacking fails, visualize raw bytes
		visualizer.VisualizePacket(responseBytes)
		return
	}

	// (11) print the parsed + human-readable response
	fmt.Println(responseMsg.String())

	// (12) visualize the response
	visualizer.VisualizePacket(responseBytes)

}
