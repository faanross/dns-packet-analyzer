package main

import (
	"flag"
	"github.com/faanross/dns-packet-analyzer/internal/models"
	"github.com/faanross/dns-packet-analyzer/internal/utils"
	"github.com/nsf/termbox-go"
	"log"
)

type AppState int

const (
	StateList AppState = iota
	StateDetail
)

type App struct {
	packets  []models.DNSPacket
	selected int
	offset   int
	state    AppState
	current  *models.DNSPacket
}

func main() {
	// read pcap from disk (provided by -pcap flag)
	var pcapFile string
	flag.StringVar(&pcapFile, "pcap", "", "Path to pcap file")
	flag.Parse()

	if pcapFile == "" {
		log.Fatal("Please provide a pcap file with -pcap flag")
	}

	// pcap has been located, extract DNS packets
	packets, err := utils.ExtractDNSPackets(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	if len(packets) == 0 {
		log.Fatal("No DNS packets found in pcap")
	}

	// Set up our  UI state struct

	app := &App{
		packets: packets,
		state:   StateList,
	}

	err = termbox.Init()
	if err != nil {
		log.Fatal(err)
	}
	defer termbox.Close()

	app.run()
}
