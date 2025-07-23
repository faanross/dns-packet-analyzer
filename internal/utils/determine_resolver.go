package utils

import (
	"fmt"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"github.com/miekg/dns"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// DetermineResolver determines the default DNS resolver configured
// for the current host independently of the exact OS
func DetermineResolver(config models.Resolver) (models.Resolver, error) {
	// if UseSystemDefaults is false we'll use the specific IP:Port
	if !config.UseSystemDefaults {
		fmt.Printf("Using manual resolver: %s:%d\n", config.IP, config.Port)
		if config.IP == "" {
			return models.Resolver{}, fmt.Errorf("manual resolver IP is not specified")
		}
		return config, nil
	}

	// If we get here means we will use default resolver
	var dnsConfig *dns.ClientConfig
	var err error

	// miekg/dns does not provide a function for using default resolver on Windows, only Darwin/Nix/BSD
	if runtime.GOOS == "windows" {
		cmd := exec.Command("nslookup", "dummy.local")
		output, _ := cmd.Output()

		// Parse the default server from nslookup output
		re := regexp.MustCompile(`Default Server:.*\r?\nAddress:\s*(.+)`)
		matches := re.FindStringSubmatch(string(output))

		if len(matches) > 1 {
			server := strings.TrimSpace(matches[1])
			dnsConfig = &dns.ClientConfig{
				Servers: []string{server},
				Port:    "53",
			}
		}
	} else {
		// This works for Linux, macOS, BSD, etc.
		dnsConfig, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	}

	if err != nil {
		return models.Resolver{}, fmt.Errorf("could not get system resolver config: %w", err)
	}

	if len(dnsConfig.Servers) == 0 {
		return models.Resolver{}, fmt.Errorf("no system DNS servers found")
	}

	// Use the primary system resolver.
	primaryServer := dnsConfig.Servers[0]
	port, _ := strconv.Atoi(dnsConfig.Port)
	if port != 53 {
		port = 53 // Default to 53 if port is not specified or invalid.
	}

	fmt.Printf("Using default DNS Resolver: %s:%d\n", primaryServer, port)

	return models.Resolver{
		UseSystemDefaults: true,
		IP:                primaryServer,
		Port:              port,
	}, nil
}
