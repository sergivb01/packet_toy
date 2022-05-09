package main

import (
	"log"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const fileName = "test.pcap"

func BenchmarkDecodePackets(b *testing.B) {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true
		packetSource.Lazy = true
		DecodePackets(packetSource)
		b.StopTimer()
	}
}

func BenchmarkDecodePackets2(b *testing.B) {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true
		packetSource.Lazy = true
		DecodePackets2(packetSource)
		b.StopTimer()
	}
}

func BenchmarkDecodePackets3(b *testing.B) {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true
		packetSource.Lazy = true
		DecodePackets3(packetSource)
		b.StopTimer()
	}
}
