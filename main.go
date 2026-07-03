package main

import (
	"fmt"
	"log"
	"strconv"

	// "errors" for when i expand the project more with functions
	// (its better to not use logs in functions and instead let the main function handle errors via log)

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

func main() {
	// packet cache to lookup packet info when requested
	packetCache := make(map[int]gopacket.Packet)
	packetCount := 0

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
	headers := []string{"No.", "Time", "Length"}
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
	detailView.SetText("Select a packet to inspect it...")

	// allow a user to select a field/packet
	table.SetSelectionChangedFunc(func(row, column int) {
		if row == 0 { // skip the row with the header in it
			return
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
				timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
				length := strconv.Itoa(packet.Metadata().Length)

				// add information rows showing the data field on the top half of the program with the packet data.
				table.SetCell(row, 0, tview.NewTableCell(strconv.Itoa(packetCount)).SetTextColor(tcell.ColorGreen))
				table.SetCell(row, 1, tview.NewTableCell(timestamp))
				table.SetCell(row, 2, tview.NewTableCell(length))

				// only keep rowLimit amount of rows/packets in memory to prevent memory leak
				if row > 200 {
					table.RemoveRow(1)
					delete(packetCache, packetCount-200)
				}
			})
		}
	}()

	// start app loop and exit if an error occurs.
	if err := tui.SetRoot(flex, true).Run(); err != nil {
		log.Fatalf("TUI Error: %v", err)
	}
}
