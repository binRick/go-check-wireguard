package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/k0kubun/pp"
	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gopkg.in/alecthomas/kingpin.v2"
)

func (w *WireguardClient) CheckDns() (bool, interface{}, error) {
	w.WriteDnsPacket()
	w.ReadDnsPacket()
	return true, ``, nil
}

var (
	DEFAULT_DNS_RECORD = `google.com`
)

var (
	dnsRecord = kingpin.Flag("dns-record", "DNS Record to lookup").Default(fmt.Sprintf("%s", DEFAULT_DNS_RECORD)).OverrideDefaultFromEnvar(`DEFAULT_DNS_RECORD`).String()
)

func (w *WireguardClient) WriteDnsPacket() {

	dns_question := fmt.Sprintf("%s.", *dnsRecord)
	dns_type := dns.TypeA

	dns_msg := new(dns.Msg)
	dns_msg.SetQuestion(dns_question, dns_type)

	dns_question_packed, err := dns_msg.Pack()
	Fatal(err)

	pp.Print(dns_msg)

	src_port := 45223

	udp := &layers.UDP{}
	udp.SrcPort = layers.UDPPort(src_port)
	udp.DstPort = layers.UDPPort(53)
	//	pp.Print(udp.String())

	req_header, req_header_err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(dns_question_packed),
		Protocol: 17, // UDP     https://golang.org/src/net/lookup.go?s=6530:6613
		TTL:      int(w.IcmpTTL),

		Src: w.ClientAddress,
		Dst: w.ServerAddress,
	}).Marshal()
	Fatal(req_header_err)

	binary.BigEndian.PutUint16(req_header[2:], uint16(ipv4.HeaderLen+len(dns_question_packed))) // fix the length endianness on BSDs
	reqData := append(append(req_header, dns_question_packed...), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(reqData[10:], ipChecksum(reqData))
	reqPacket := make([]byte, 16)
	reqPacket[0] = 4                                           // Type: Data
	reqPacket[1] = 0                                           // Reserved
	reqPacket[2] = 0                                           // Reserved
	reqPacket[3] = 0                                           // Reserved
	binary.LittleEndian.PutUint32(reqPacket[4:], w.TheirIndex) // Their index
	binary.LittleEndian.PutUint64(reqPacket[8:], 0)            // Nonce
	clear_packet := reqPacket
	enc_packet, err := w.SendCipher.Encrypt(reqPacket, nil, reqData) // Payload data
	Fatal(err)

	if _, err := w.Connection.Write(enc_packet); err != nil {
		log.Fatalf("error writing reqData message: %s", err)
	}

	msg := fmt.Sprintf(`

Wrote %d bytes to connection

Encrypted packet %d bytes
clear_packet %d bytes
reqData %d bytes
header %d bytes
dns_question_packed %d bytes
dns_question: %s
dns_type: %d

`, len(reqPacket), len(enc_packet), len(clear_packet), len(reqData), len(req_header), len(dns_question_packed), dns_question, dns_type,
	)
	fmt.Println(msg)

	return
}

func (w *WireguardClient) ReadDnsPacket() {
	w.ReadIcmpPacketStarted = time.Now()
	replyPacket := make([]byte, 80)
	fmt.Printf(`

waiting for reply Packet...........

`)
	n, err := w.Connection.Read(replyPacket)

	fmt.Printf(`

read reply Packet!

`)
	Fatal(err)

	w.ReadIcmpPacketDuration = time.Since(w.ReadIcmpPacketStarted)
	if err != nil {
		log.Fatalf("error reading reqData reply message: %s", err)
	}
	replyPacket = replyPacket[:n]
	if replyPacket[0] != 4 { // Type: Data
		log.Fatalf("unexpected reply packet type: %d", replyPacket[0])
	}
	if replyPacket[1] != 0 || replyPacket[2] != 0 || replyPacket[3] != 0 {
		log.Fatalf("reply packet has non-zero reserved fields")
	}
	replyPacket, err = w.ReceiveCipher.Decrypt(nil, nil, replyPacket[16:])
	if err != nil {
		log.Fatalf("error decrypting reply packet: %s", err)
	}
	replyHeaderLen := int(replyPacket[0]&0x0f) << 2
	replyLen := binary.BigEndian.Uint16(replyPacket[2:])
	replyMessage, err := icmp.ParseMessage(1, replyPacket[replyHeaderLen:replyLen])
	if err != nil {
		log.Fatalf("error parsing echo: %s", err)
	}
	echo, ok := replyMessage.Body.(*icmp.Echo)
	if !ok {
		log.Fatalf("unexpected reply body type %T", replyMessage.Body)
	}

	if echo.ID != w.IcmpID || echo.Seq != w.IcmpSequenceID || string(echo.Data) != w.IcmpMessage {
		log.Fatalf("incorrect echo response: %#v", echo)
	}

	return
}
