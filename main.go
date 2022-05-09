package main

import (
	hex2 "encoding/hex"
	"log"
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

type packetData struct {
	Ethernet struct {
		SrcAddress  string   `json:"source"`
		DstAddress  string   `json:"destination"`
		Type        string   `json:"type"`
		Length      uint16   `json:"length"`
		RawContents []string `json:"raw_contents"`
	} `json:"ethernet"`
	IP struct {
		TTL         uint8    `json:"ttl"`
		Protocol    string   `json:"protocol"`
		SrcAddress  string   `json:"source"`
		DstAddress  string   `json:"destination"`
		Length      uint16   `json:"length"`
		RawContents []string `json:"raw_contents"`
	} `json:"ip"`
	TCP struct {
		SrcPort     uint16   `json:"src_port"`
		DstPort     uint16   `json:"dst_port"`
		RawContents []string `json:"raw_contents"`
	} `json:"tcp"`
	Payload []string `json:"payload"`
}

func DecodePackets(packets <-chan gopacket.Packet) {
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	decodedLayers := make([]gopacket.LayerType, 4, 4)

	for packet := range packets {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			log.Printf("Trouble decoding layers: %v", err)
		}

		var remoteAddr string
		pk := &packetData{}
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeEthernet:
				pk.Ethernet.SrcAddress = eth.SrcMAC.String()
				pk.Ethernet.DstAddress = eth.DstMAC.String()
				pk.Ethernet.Type = eth.EthernetType.String()
				pk.Ethernet.Length = eth.Length
				pk.Ethernet.RawContents = hex(eth.Contents)
			case layers.LayerTypeIPv4:
				pk.IP.TTL = ip4.TTL
				pk.IP.Protocol = ip4.Protocol.String()
				pk.IP.SrcAddress = ip4.SrcIP.String()
				pk.IP.DstAddress = ip4.DstIP.String()
				pk.IP.Length = ip4.Length
				pk.IP.RawContents = hex(ip4.Contents)
			case layers.LayerTypeIPv6:
				pk.IP.TTL = ip6.HopLimit
				pk.IP.Protocol = ip6.NextHeader.String()
				pk.IP.SrcAddress = ip6.SrcIP.String()
				pk.IP.DstAddress = ip6.DstIP.String()
				pk.IP.Length = ip6.Length
				pk.IP.RawContents = hex(ip6.Contents)
			case layers.LayerTypeTCP:
				pk.TCP.SrcPort = uint16(tcp.SrcPort)
				pk.TCP.DstPort = uint16(tcp.DstPort)
				pk.TCP.RawContents = hex(tcp.Contents)
				pk.Payload = hex(tcp.Payload)
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

func DecodePackets2(packets <-chan gopacket.Packet) {

	for packet := range packets {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		pk := &packetData{}

		eth, _ := ethLayer.(*layers.Ethernet)

		pk.Ethernet.SrcAddress = eth.SrcMAC.String()
		pk.Ethernet.DstAddress = eth.DstMAC.String()
		pk.Ethernet.Type = eth.EthernetType.String()
		pk.Ethernet.Length = eth.Length
		pk.Ethernet.RawContents = hex(eth.Contents)

		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer == nil {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			ip4, _ := ip4Layer.(*layers.IPv4)
			pk.IP.TTL = ip4.TTL
			pk.IP.Protocol = ip4.Protocol.String()
			pk.IP.SrcAddress = ip4.SrcIP.String()
			pk.IP.DstAddress = ip4.DstIP.String()
			pk.IP.Length = ip4.Length
			pk.IP.RawContents = hex(ip4.Contents)
		} else {
			ip6, _ := ip6Layer.(*layers.IPv6)

			pk.IP.TTL = ip6.HopLimit
			pk.IP.Protocol = ip6.NextHeader.String()
			pk.IP.SrcAddress = ip6.SrcIP.String()
			pk.IP.DstAddress = ip6.DstIP.String()
			pk.IP.Length = ip6.Length
			pk.IP.RawContents = hex(ip6.Contents)
		}

		tcp, _ := tcpLayer.(*layers.TCP)
		pk.TCP.SrcPort = uint16(tcp.SrcPort)
		pk.TCP.DstPort = uint16(tcp.DstPort)
		pk.TCP.RawContents = hex(tcp.Contents)
		pk.Payload = hex(tcp.Payload)

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
	handle, err := pcap.OpenLive("lo", defaultSnapLen, true,
		pcap.BlockForever)
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

	packets := packetSource.Packets()
	DecodePackets(packets)
}

func hex(b []byte) []string {
	// split by lines and ignore the last empty string
	// return strings.SplitN(hex2.Dump(b), "\n", len(b)/16)
	// TODO: optimize
	split := strings.Split(hex2.Dump(b), "\n")
	return split[:len(split)-1]
}
