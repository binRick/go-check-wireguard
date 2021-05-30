package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

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

func checkSum(msg []byte) uint16 {
	sum := 0
	for n := 1; n < len(msg)-1; n += 2 {
		sum += int(msg[n])*256 + int(msg[n+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var ans = uint16(^sum)
	return ans
}

func (w *WireguardClient) WriteDnsPacket() {

	dns_question_packed := wgc.dns_buffer()

	w.SetCheckDestination()

	req_header, req_header_err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(dns_question_packed),
		Protocol: 17, // UDP     https://golang.org/src/net/lookup.go?s=6530:6613
		TTL:      int(w.IcmpTTL),
		Src:      w.ClientAddress,
		Dst:      w.GetCheckDestDestination(),
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

	bytes_written, err := w.Connection.Write(enc_packet)
	Fatal(err)

	msg := fmt.Sprintf(`

Wrote %d bytes to connection
Encrypted packet %d bytes
clear_packet %d bytes
reqData %d bytes
header %d bytes
dns_question_packed %d bytes

`,
		bytes_written,
		len(enc_packet), len(clear_packet), len(reqData), len(req_header), len(dns_question_packed),
	)
	if false {
		fmt.Println(msg)
	}
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
