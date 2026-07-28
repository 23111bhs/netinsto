package main

import (
	"testing" // so that we can use go test as its supposed to be used

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// basically what this function does is it creates a fake packet with designated TCP and IPv4 information
// and then checks if the filterPacketType function works correctly by checking against the src ip, dst ip, and protocol
func TestTCPTypePacket(test *testing.T) {

	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 20}, // and a local IPv4 address to match this
		DstIP: []byte{8, 8, 8, 8},      // google's dns as this is purely theoretical
	}

	tcp := &layers.TCP{
		SrcPort: 12345, // 12345 because why not?
		DstPort: 80,    // for http catching
	}

	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers( // formatting
		buffer,
		gopacket.SerializeOptions{},
		ip,
		tcp,
	)

	if err != nil { // error catching for the 'packet'
		test.Fatal(err)
	}

	packet := gopacket.NewPacket( // create packet with the buffer and layers
		buffer.Bytes(),
		layers.LayerTypeIPv4,
		gopacket.Default,
	)

	src, dst, proto := filterPacketType(packet)

	if src != "192.168.1.20" { // check for malformed src ip
		test.Errorf(
			"Expected source IP 192.168.1.20, got %s",
			src,
		)
	}

	if dst != "8.8.8.8" { // check for malformed dest ip
		test.Errorf(
			"Expected destination IP 8.8.8.8, got %s",
			dst,
		)
	}

	if proto != "TCP" { // check for malformed protocol
		test.Errorf(
			"Expected TCP, got %s",
			proto,
		)
	}
}
