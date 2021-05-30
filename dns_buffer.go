package main

import (
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func RandInt(min, max int32) int32 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int31n(max-min) + min
}

//srcIP := fmt.Sprintf("%d.%d.%d.%d", RandInt(8, 120), RandInt(5, 200), RandInt(5, 250), RandInt(2, 255))

func (w *WireguardClient) dns_buffer() []byte {

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	quetions := []layers.DNSQuestion{layers.DNSQuestion{
		Name:  []byte(*dnsRecord),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}}

	dns := layers.DNS{
		ID:        0x22ff,
		QR:        true,
		QDCount:   1,
		Questions: quetions,
	}

	ipv4 := layers.IPv4{
		SrcIP:    wgc.ClientAddress,
		DstIP:    wgc.GetCheckDestDestination(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	//pp.Print(wgc)

	udp := layers.UDP{
		SrcPort: 54321,
		DstPort: layers.UDPPort(wgc.CheckDestinationPort),
	}

	udp.SetNetworkLayerForChecksum(&ipv4)

	err := gopacket.SerializeLayers(buf, opts, &udp, &dns)
	///////err := gopacket.SerializeLayers(buf, opts, &ether, &ipv4, &udp, &dns)
	Fatal(err)
	//	err = handler.WritePacketData(buf.Bytes())
	return buf.Bytes()
}
