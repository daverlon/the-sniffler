package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	INTERFACE_NAME = `\Device\NPF_{A1F8E665-100D-4FA6-9A24-E9B923774E4E}`
)

var (
	QUERY_PACKET_HEADER = []byte{0xFF, 0xFF, 0xFF, 0xFF}
)

func listNetDevices() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		fmt.Println("Interface Name:", device.Name)
		fmt.Println()
	}
	fmt.Println()
}

func main() {

	handle, err := pcap.OpenLive(INTERFACE_NAME, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	fmt.Println("Listening for packets...\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	_ = handle.SetBPFFilter("dst port 27015")

	for packet := range packetSource.Packets() {

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			log.Println("UDP layer not found")
			continue
		}
		udpPacket, _ := udpLayer.(*layers.UDP)

		// Extract the payload from the UDP packet
		payload := udpPacket.Payload
		// fmt.Println(payload)

		if bytes.Equal(payload[0:4], QUERY_PACKET_HEADER) {
			fmt.Println("Found Query Packet. Skipping.")
			continue
		}

		fmt.Println(hex.EncodeToString(payload))
		fmt.Println()
		continue
		buf := BitBuffer{payload, 0}

		seqnum := buf.ReadLong()
		seqacknum := buf.ReadLong()
		flags := buf.ReadByte()

		fmt.Println("Seqnum:", seqnum)
		fmt.Println("Seqacknum:", seqacknum)
		fmt.Println("flags:", fmt.Sprintf("%b\n", flags))

		// checksum

		checksum := buf.ReadShort()
		fmt.Println("checksum:", checksum)

		offset := buf.cur_bit >> 3
		chck := buf.DoChecksum(offset)
		fmt.Println("ck2:", chck)
		if checksum == chck {
			fmt.Println("FOUND MATCH!")
			break
		}

		//bitbuf := bitio.NewCountReader(bytes.NewBuffer(data))

		fmt.Println("---------------------------")
	}

}
