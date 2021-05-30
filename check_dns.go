package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cirocosta/rawdns/lib"
	"github.com/google/gopacket/layers"
	"github.com/k0kubun/pp"
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
	_dns_question := fmt.Sprintf("%s", *dnsRecord)

	queryMsg := &lib.Message{
		Header: lib.Header{
			ID:      10,
			QR:      0,
			Opcode:  lib.OpcodeQuery,
			QDCOUNT: 1,
			RD:      1,
		},
		Questions: []*lib.Question{
			{
				QNAME:  _dns_question,
				QTYPE:  lib.QTypeA,
				QCLASS: lib.QClassIN,
			},
		},
	}
	dns_question_packed, err := queryMsg.Marshal()
	Fatal(err)

	pp.Print(dns_question_packed)

	src_port := 45223

	var check_dst net.IP
	var check_port int
	switch *destHost {
	case `default`:
		check_dst = w.ServerAddress
	default:
		check_dst = net.ParseIP(*destHost)
	}
	switch *destPort {
	case 0:
		check_port = 53
	default:
		check_port = *destPort
	}

	udp := &layers.UDP{}
	udp.SrcPort = layers.UDPPort(src_port)
	udp.DstPort = layers.UDPPort(check_port)
	pp.Print(udp)

	_pl := dns_question_packed
	pl := get_raw_udp_payload(_pl)
	fmt.Println(check_dst)
	w.SetCheckDestination()
	req_header, req_header_err := (&ipv4.Header{
		Version: ipv4.Version,
		Len:     ipv4.HeaderLen,
		//TotalLen: ipv4.HeaderLen + len(pl),
		TotalLen: ipv4.HeaderLen + len(dns_question_packed),
		Protocol: 17, // UDP     https://golang.org/src/net/lookup.go?s=6530:6613
		TTL:      int(w.IcmpTTL),
		Src:      w.ClientAddress,
		//		Dst:      check_dst,
		Dst: w.GetCheckDestDestination(),
	}).Marshal()
	Fatal(req_header_err)

	//	_pl := []byte(`yyyyadsa8ys97da`)
	fmt.Printf(`


get_raw_udp_payload: %d bytes:


%s



`,
		len(pl),
		pl,
	)

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

	bytes_written, err := w.Connection.Write(enc_packet)
	Fatal(err)

	msg := fmt.Sprintf(`

Wrote %d bytes to connection
Encrypted packet %d bytes
clear_packet %d bytes
reqData %d bytes
header %d bytes
dns_question_packed %d bytes
dns_question: %s

`,
		bytes_written,
		len(enc_packet), len(clear_packet), len(reqData), len(req_header), len(dns_question_packed), dns_question,
	)
	fmt.Println(msg)

	return
}

func (w *WireguardClient) ReadDnsPacket() {
	w.ReadPacketStarted = time.Now()
	replyPacket := make([]byte, 80)
	fmt.Printf(`

waiting for reply Packet...........

`)
	wait_started := time.Now()
	n, err := w.Connection.Read(replyPacket)

	fmt.Printf(`

read reply Packet after %d ms!

`, time.Since(wait_started).Milliseconds())
	Fatal(err)

	w.ReadPacketDuration = time.Since(w.ReadPacketStarted)
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
