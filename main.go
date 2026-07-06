package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

// packet cache to lookup packet info when requested
var packetCache = make(map[int]gopacket.Packet)
var packetCount = 0

func main() {
	const rowLimit int = 200 // max amount of packets in history

	// initial setup for traffic capture
	devices, err := pcap.FindAllDevs()
	if err != nil { // if err is not nil, an error has occurred and the program will display the below message. otherwise, pass.
		log.Fatalf("Failed to find network devices: %v", err)
	}

	// if the amount of devices is 0, log the below error in the terminal
	if len(devices) == 0 {
		log.Fatalf("No network devices found.")
	}
	device := devices[0].Name

	handle, err := pcap.OpenLive(device, 2048, true, pcap.BlockForever)
	if err != nil { // if the program fails to open/inspect on the interface for whatever reason, stop and log the below message in the terminal.
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	// start tview (TUI)
	tui := tview.NewApplication()

	// define top bar (----- netinsto ----- thing)
	table := tview.NewTable().SetSelectable(true, false)
	table.SetBorder(true).SetTitle(fmt.Sprintf(" netinsto [%s] ", device))

	// set headers of tables
	headers := []string{"No.", "Time", "Source", "Destination", "Protocol", "Length"}
	for col, header := range headers {
		table.SetCell(0, col, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))
	}

	// bottom packet details section showing packet information
	detailView := tview.NewTextView().SetDynamicColors(true).SetChangedFunc(func() {
		tui.Draw() // if the packet info updates, redraw the info
	})
	detailView.SetBorder(true).SetTitle(" Packet Details ")
	detailView.SetText("Select a packet above to inspect its layers...")

	// allow a user to select a field/packet
	table.SetSelectionChangedFunc(func(row, column int) {
		if row == 0 { // skip the row with the header in it
			return
		}
		// get packet ID from the string of the first row
		idStr := table.GetCell(row, 0).Text
		id, _ := strconv.Atoi(idStr)

		if packet, exists := packetCache[id]; exists {
			detailView.SetText(getPacketDetails(packet))
		}
	})

	// use flexbox for TUI layout
	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).      // focus user on first half (packet section)
		AddItem(detailView, 0, 1, false) // define bottom half (details section)

	// keybinds (esc or ctrl + c to quit)
	tui.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyCtrlC {
			tui.Stop()
		}
		return event
	})

	// background packet sniffing and UI updates
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			packetCount++
			packetCache[packetCount] = packet // store in memory

			// push layout updates to the main UI thread
			tui.QueueUpdateDraw(func() {
				row := table.GetRowCount()

				// format packet metadata for the TUI tables
				timestamp := packet.Metadata().Timestamp.Format("15:04:05.000") // to anyone that hasnt used go before, this number looks random but is needed to format time correctly.
				length := strconv.Itoa(packet.Metadata().Length)
				srcIP, dstIP, proto := filterPacketType(packet)

				// add information rows showing the data field on the top half of the program with the packet data.
				table.SetCell(row, 0, tview.NewTableCell(strconv.Itoa(packetCount)).SetTextColor(tcell.ColorGreen))
				table.SetCell(row, 1, tview.NewTableCell(timestamp))
				table.SetCell(row, 2, tview.NewTableCell(srcIP).SetTextColor(tcell.ColorGreen))
				table.SetCell(row, 3, tview.NewTableCell(dstIP).SetTextColor(tcell.ColorGreen))
				table.SetCell(row, 4, tview.NewTableCell(proto).SetTextColor(tcell.ColorBlue))
				table.SetCell(row, 5, tview.NewTableCell(length))

				// only keep rowLimit amount of rows/packets in memory to prevent memory leak
				if row > rowLimit {
					table.RemoveRow(1)
					delete(packetCache, packetCount-rowLimit)
				}
			})
		}
	}()

	// start app loop
	if err := tui.SetRoot(flex, true).Run(); err != nil {
		log.Fatalf("TUI Error: %v", err)
	}
}

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
	}

	// return source IP, destination IP, and protocol of packet.
	return src, dst, proto
}

// define details field at the bottom half of the program.
func getPacketDetails(packet gopacket.Packet) string {
	output := "" // blank so that for every field the information gets matched, it can be filled.

	// layer 2 (MAC, LLC, Ethernet) dl for Data Link (Layer)
	if dlLayer := packet.Layer(layers.LayerTypeEthernet); dlLayer != nil {
		dlMAC, _ := dlLayer.(*layers.Ethernet)
		output += fmt.Sprintf("[yellow][ Layer 2 Ethernet/MAC ][-]\n  Source MAC:      %s\n  Destination MAC: %s\n\n", dlMAC.SrcMAC, dlMAC.DstMAC)
	}

	// layer 3 (IPv4) net for Network (Layer)
	if netLayer := packet.Layer(layers.LayerTypeIPv4); netLayer != nil {
		netIPv4, _ := netLayer.(*layers.IPv4)
		output += fmt.Sprintf("[teal][ Layer 3 IPv4 ][-]\n  Source IP:       %s\n  Destination IP:  %s\n  TTL:             %d\n\n", netIPv4.SrcIP, netIPv4.DstIP, netIPv4.TTL)
	}

	// layer 3 (IPv6)
	if netLayer := packet.Layer(layers.LayerTypeIPv6); netLayer != nil {
		netIPv6, _ := netLayer.(*layers.IPv6)
		output += fmt.Sprintf("[teal][ Layer 3 IPv6 ][-]\n  Source IP:       %s\n  Destination IP:  %s\n  TTL:			   %d\n\n", netIPv6.SrcIP, netIPv6.DstIP, netIPv6.HopLimit)
	}

	// layer 4 (TCP/transport) trans for Transport (Layer)
	if transLayer := packet.Layer(layers.LayerTypeTCP); transLayer != nil {
		transTCP, _ := transLayer.(*layers.TCP)
		output += fmt.Sprintf("[purple][ Layer 4 TCP ][-]\n  Src Port:  %s\n  Dst Port:  %s\n  Seq Num:   %d\n  Ack Num:   %d\n\n", transTCP.SrcPort, transTCP.DstPort, transTCP.Seq, transTCP.Ack)
	}

	// layer 4 (UDP/transport)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		transUDP, _ := udpLayer.(*layers.UDP)
		output += fmt.Sprintf("[purple][ Layer 4 UDP ][-]\n  Src Port:  %s\n  Dst Port:  %s\n  Length:    %d\n\n", transUDP.SrcPort, transUDP.DstPort, transUDP.Length)
	}

	// layer 7 (raw application payload data)
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		output += fmt.Sprintf("[green][ Layer 7 Raw Payload Data (%d bytes) ][-]\n", len(appLayer.Payload()))
		// show the raw chunks of data inside of the packet
		output += fmt.Sprintf("  %q\n", appLayer.Payload())
	}

	// return the packet type
	return output
}
