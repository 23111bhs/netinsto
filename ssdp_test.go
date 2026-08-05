package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestSSDPTypePacket(test *testing.T) {
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 0, 0, 1},        // local IPv4 type address
		DstIP:    []byte{239, 255, 255, 250}, // ip structure (multicast aaddress for ssdp)
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 1900, // ssdp src port
		DstPort: 1900, // ssdp dst port
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer() // create new buffer to hold packet data
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp); err != nil {
		test.Fatal(err) // check for errors in packet
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	src, dst, proto := filterPacketType(packet)

	if src != "10.0.0.1" {
		test.Errorf("expected source IP 10.0.0.1, got %s", src)
	}
	if dst != "239.255.255.250" {
		test.Errorf("expected destination IP 239.255.255.250, got %s", dst)
	}
	if proto != "SSDP" {
		test.Errorf("expected SSDP, got %s", proto)
	}
}
