package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// filter packet/protocol type
func filterPacketType(packet gopacket.Packet) (string, string, string) {
	// if the packet is malformed/unrecognizable then give it the below names so that they dont show as blank
	src, dst, proto := "N/A", "N/A", "Other"

	// use mac addresses for non ip packets and detect ieee 1905.1 through ethertype 0x893a
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		if eth.EthernetType == layers.EthernetType(0x893a) {
			proto = "ieee1905"
		}
		if src == "N/A" {
			src = eth.SrcMAC.String()
		}
		if dst == "N/A" {
			dst = eth.DstMAC.String()
		}
	}

	// get destination and source IP address
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	}
	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		src = ip6.SrcIP.String()
		dst = ip6.DstIP.String()
		if proto == "Other" {
			proto = "IPv6"
		}
	}

	// check protocol
	if packet.Layer(layers.LayerTypeTCP) != nil {
		proto = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		proto = "UDP"
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 1900 || udp.DstPort == 1900 {
			proto = "SSDP"
		}
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		proto = "ICMP"
	} else if packet.Layer(layers.LayerTypeARP) != nil {
		proto = "ARP"
	} else if packet.Layer(layers.LayerTypeDNS) != nil {
		proto = "DNS"
	}

	// return source IP or MAC, destination IP or MAC, and protocol of packet.
	return src, dst, proto
}
