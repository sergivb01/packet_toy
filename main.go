package main

import (
	hex2 "encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

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

func DecodePackets(packets *gopacket.PacketSource) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	decodedLayers := make([]gopacket.LayerType, 4, 4)

	for {
		packet, err := packets.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}

		if err := parser.DecodeLayers(packet.Data(), &decodedLayers); err != nil {
			log.Printf("Trouble decoding layers: %v", err)
		}

		var remoteAddr string
		pk := &packetData{
			Payload: hex(tcp.Payload),
		}
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeEthernet:
				pk.Ethernet = ethernetData{
					SrcAddress:  eth.SrcMAC.String(),
					DstAddress:  eth.DstMAC.String(),
					Type:        eth.EthernetType.String(),
					Length:      eth.Length,
					RawContents: hex(eth.Contents),
				}
			case layers.LayerTypeIPv4:
				pk.IP = ipData{
					TTL:         ip4.TTL,
					Protocol:    ip4.Protocol.String(),
					SrcAddress:  ip4.SrcIP.String(),
					DstAddress:  ip4.DstIP.String(),
					Length:      ip4.Length,
					RawContents: hex(ip4.Contents),
				}
			case layers.LayerTypeIPv6:
				pk.IP = ipData{
					TTL:         ip6.HopLimit,
					Protocol:    ip6.NextHeader.String(),
					SrcAddress:  ip6.SrcIP.String(),
					DstAddress:  ip6.DstIP.String(),
					Length:      ip6.Length,
					RawContents: hex(ip6.Contents),
				}
			case layers.LayerTypeTCP:
				pk.TCP = tcpData{
					SrcPort:     uint16(tcp.SrcPort),
					DstPort:     uint16(tcp.DstPort),
					RawContents: hex(tcp.Contents),
				}
			}
		}

		if tcp.DstPort == 80 {
			remoteAddr = pk.IP.SrcAddress
		} else {
			remoteAddr = pk.IP.DstAddress
		}
		_ = remoteAddr
		// log.Printf("took %s", time.Since(s))
		// b, err := json.Marshal(*pk)
		// if err != nil {
		// 	panic(err)
		// }
		// _, _ = os.Stderr.Write(b)
		// _, _ = os.Stderr.Write([]byte("\n"))
	}
}

func DecodePackets3(packets *gopacket.PacketSource) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		payload gopacket.Payload
	)

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc = dlc.Put(&eth)
	dlc = dlc.Put(&ip4)
	dlc = dlc.Put(&ip6)
	dlc = dlc.Put(&tcp)
	dlc = dlc.Put(&payload)

	// you may specify some meaningful DecodeFeedback
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

	for {
		packet, err := packets.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}

		lt, err := decoder(packet.Data(), &decoded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			continue
		}
		if lt != gopacket.LayerTypeZero {
			fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", lt)
			continue
		}

		var remoteAddr string
		pk := &packetData{
			Payload: hex(tcp.Payload),
		}
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeEthernet:
				pk.Ethernet = ethernetData{
					SrcAddress:  eth.SrcMAC.String(),
					DstAddress:  eth.DstMAC.String(),
					Type:        eth.EthernetType.String(),
					Length:      eth.Length,
					RawContents: hex(eth.Contents),
				}
			case layers.LayerTypeIPv4:
				pk.IP = ipData{
					TTL:         ip4.TTL,
					Protocol:    ip4.Protocol.String(),
					SrcAddress:  ip4.SrcIP.String(),
					DstAddress:  ip4.DstIP.String(),
					Length:      ip4.Length,
					RawContents: hex(ip4.Contents),
				}
			case layers.LayerTypeIPv6:
				pk.IP = ipData{
					TTL:         ip6.HopLimit,
					Protocol:    ip6.NextHeader.String(),
					SrcAddress:  ip6.SrcIP.String(),
					DstAddress:  ip6.DstIP.String(),
					Length:      ip6.Length,
					RawContents: hex(ip6.Contents),
				}
			case layers.LayerTypeTCP:
				pk.TCP = tcpData{
					SrcPort:     uint16(tcp.SrcPort),
					DstPort:     uint16(tcp.DstPort),
					RawContents: hex(tcp.Contents),
				}
			}
		}

		if tcp.DstPort == 80 {
			remoteAddr = pk.IP.SrcAddress
		} else {
			remoteAddr = pk.IP.DstAddress
		}
		_ = remoteAddr
	}
}

func DecodePackets2(packets *gopacket.PacketSource) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		packet, err := packets.NextPacket()
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
			remoteAddr = pk.IP.SrcAddress
		} else {
			remoteAddr = pk.IP.DstAddress
		}
		_ = remoteAddr
	}
}

func main() {
	handle, err := pcap.OpenLive("lo", defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ip and tcp and (dst port 80 or src port 80)"); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true

	DecodePackets(packetSource)
}

func hex(b []byte) []string {
	// split by lines and ignore the last empty string
	// return strings.SplitN(hex2.Dump(b), "\n", len(b)/16)
	// TODO: optimize
	split := strings.Split(hex2.Dump(b), "\n")
	return split[:len(split)-1]
}
