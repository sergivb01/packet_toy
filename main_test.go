package main

import (
	"log"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func BenchmarkDecodePackets(b *testing.B) {
	handle, err := pcap.OpenOffline("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	for i := 0; i < b.N; i++ {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		b.StartTimer()
		DecodePackets(packetSource.Packets())
		b.StopTimer()
	}
}

func BenchmarkDecodePackets2(b *testing.B) {
	handle, err := pcap.OpenOffline("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	for i := 0; i < b.N; i++ {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		b.StartTimer()
		DecodePackets2(packetSource.Packets())
		b.StopTimer()
	}
}
