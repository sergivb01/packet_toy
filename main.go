package main

import (
	hex2 "encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	// defaultSnapLen = 262144
	defaultSnapLen = 9216 // TODO: investigate adequate number, currently max jumbo ethernet frame
)

type ethernetData struct {
	SrcAddress  string   `json:"source"`
	DstAddress  string   `json:"destination"`
	Type        string   `json:"type"`
	Length      uint16   `json:"length"`
	RawContents []string `json:"raw_contents"`
}

type ipData struct {
	TTL         uint8    `json:"ttl"`
	Protocol    string   `json:"protocol"`
	SrcAddress  string   `json:"source"`
	DstAddress  string   `json:"destination"`
	Length      uint16   `json:"length"`
	RawContents []string `json:"raw_contents"`
}

type tcpData struct {
	SrcPort     uint16   `json:"src_port"`
	DstPort     uint16   `json:"dst_port"`
	RawContents []string `json:"raw_contents"`
}

type packetData struct {
	Ethernet ethernetData `json:"ethernet"`
	IP       ipData       `json:"ip"`
	TCP      tcpData      `json:"tcp"`
	Payload  []string     `json:"payload"`
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s\n", r.RemoteAddr)
		})
		http.ListenAndServe("localhost:8080", nil)
	}()

	handle, err := pcap.OpenLive("lo", defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ip and tcp and (dst port 80 or src port 8080)"); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	capture(c, packetSource)

	log.Printf("shutting down :P")
}

type abc struct {
	lock *sync.Mutex
	data map[string][]packetData
}

var test = abc{
	lock: &sync.Mutex{},
	data: make(map[string][]packetData),
}

func capture(c chan os.Signal, packetSource *gopacket.PacketSource) {
	for {
		select {
		case <-c:
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		tcp, _ := tcpLayer.(*layers.TCP)
		eth, _ := ethLayer.(*layers.Ethernet)

		pk := &packetData{
			Ethernet: ethernetData{
				SrcAddress:  eth.SrcMAC.String(),
				DstAddress:  eth.DstMAC.String(),
				Type:        eth.EthernetType.String(),
				Length:      eth.Length,
				RawContents: hex(eth.Contents),
			},
			TCP: tcpData{
				SrcPort:     uint16(tcp.SrcPort),
				DstPort:     uint16(tcp.DstPort),
				RawContents: hex(tcp.Contents),
			},
			Payload: hex(tcp.Payload),
		}

		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6, _ := ip6Layer.(*layers.IPv6)
			pk.IP = ipData{
				TTL:         ip6.HopLimit,
				Protocol:    ip6.NextHeader.String(),
				SrcAddress:  ip6.SrcIP.String(),
				DstAddress:  ip6.DstIP.String(),
				Length:      ip6.Length,
				RawContents: hex(ip6.Contents),
			}
		} else {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			ip4, _ := ip4Layer.(*layers.IPv4)
			pk.IP = ipData{
				TTL:         ip4.TTL,
				Protocol:    ip4.Protocol.String(),
				SrcAddress:  ip4.SrcIP.String(),
				DstAddress:  ip4.DstIP.String(),
				Length:      ip4.Length,
				RawContents: hex(ip4.Contents),
			}
		}

		var remoteAddr string
		if tcp.DstPort == 80 {
			remoteAddr = fmt.Sprintf("%s:%d", pk.IP.SrcAddress, pk.TCP.SrcPort)
		} else {
			remoteAddr = fmt.Sprintf("%s:%d", pk.IP.DstAddress, pk.TCP.DstPort)
		}

		test.lock.Lock()
		test.data[remoteAddr] = append(test.data[remoteAddr], *pk)
		test.lock.Unlock()
	}
}

// hex converts a byte array into hexdump format
func hex(b []byte) []string {
	split := strings.Split(hex2.Dump(b), "\n")
	return split[:len(split)-1]
}
