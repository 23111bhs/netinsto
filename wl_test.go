package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestIEEE1905TypePacket(test *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0e, 0x1e, 0x89, 0xd4, 0x20}, // random mac address
		DstMAC:       []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x13}, // ieee 1905.1 multicast mac address
		EthernetType: layers.EthernetType(0x893a),                // set maching for ieee 1905.1 ethertype
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, eth); err != nil {
		test.Fatal(err) // check for errors in packet
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default) // create packet with buffer and layers
	src, dst, proto := filterPacketType(packet)                                              // send for filtering

	if src != "00:0e:1e:89:d4:20" { // check for malformed src mac
		test.Errorf("expected source MAC 00:0e:1e:89:d4:20, got %s", src)
	}
	if dst != "01:80:c2:00:00:13" { // check for malformed dst mac
		test.Errorf("expected destination MAC 01:80:c2:00:00:13, got %s", dst)
	}
	if proto != "ieee1905" {
		test.Errorf("expected ieee1905, got %s", proto)
	}
}
