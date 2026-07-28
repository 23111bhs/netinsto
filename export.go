package main

import (
	"os"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// saveSessionToPcap writes all currently cached packets to a .pcap file
func saveSessionToPcap(filename string) error {
	if !strings.HasSuffix(filename, ".pcap") {
		filename += ".pcap"
	}

	f, err := os.Create(filename) // create the file with the filename chosen by the
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f) // allow writing to a file in .pcap form

	// make file header 65536 byes and set it to ethernet link
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err // if an error happens when writing the file head, return err
	}

	// packetCache and packetCount are global variables (from main.go)
	for i := 1; i <= packetCount; i++ {
		packet, exists := packetCache[i]
		if !exists {
			continue
		}

		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			continue
		}
	}

	return nil
}
