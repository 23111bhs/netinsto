package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// filter packet/protocol type
func filterPacketType(packet gopacket.Packet) (string, string, string) {
	// if the packet is malformed/unrecognizable then give it the below names so that they dont show as blank
	src, dst, proto := "N/A", "N/A", "Other"

	// get destination and source IP address
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	}

	// check protocol
	if packet.Layer(layers.LayerTypeTCP) != nil {
		proto = "TCP"
	} else if packet.Layer(layers.LayerTypeUDP) != nil {
		proto = "UDP"
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		proto = "ICMP"
	} else if packet.Layer(layers.LayerTypeARP) != nil {
		proto = "ARP"
	} else if packet.Layer(layers.LayerTypeDNS) != nil {
		proto = "DNS"
	}

	// return source IP, destination IP, and protocol of packet.
	return src, dst, proto
}
