package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestIPv6TypePacket(test *testing.T) {
	ip6 := &layers.IPv6{
		SrcIP:      net.ParseIP("fe80::1"), // use link local ipv6 addresses for testing
		DstIP:      net.ParseIP("fe80::2"),
		NextHeader: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 1234,
		DstPort: 5678,
	}
	udp.SetNetworkLayerForChecksum(ip6) // set network layer for checksum

	buffer := gopacket.NewSerializeBuffer() // init buffer
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip6, udp); err != nil {
		test.Fatal(err) // check for errors
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default) // create packet buffer and layers
	src, dst, proto := filterPacketType(packet)

	if src != "fe80::1" { // check for runt src ip
		test.Errorf("expected source IP fe80::1, got %s", src)
	}
	if dst != "fe80::2" { // check for runt dst ip
		test.Errorf("expected destination IP fe80::2, got %s", dst)
	}
	if proto != "UDP" {
		test.Errorf("expected UDP, got %s", proto)
	}
}
