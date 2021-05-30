package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func (w *WireguardClient) ReadICMPPacket1() {
	w.ReadIcmpPacketStarted = time.Now()
	//	time.Sleep(10 * time.Second)
	replyPacket := make([]byte, 80)
	n, err := w.Connection.Read(replyPacket)
	w.ReadIcmpPacketDuration = time.Since(w.ReadIcmpPacketStarted)
	if err != nil {
		log.Fatalf("error reading ping reply message: %s", err)
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

func (w *WireguardClient) WriteICMPPacket1() {

	var icmp_dest net.IP
	switch *icmpDestination {
	case `default`:
		icmp_dest = w.ServerAddress
	default:
		icmp_dest = net.ParseIP(*icmpDestination)
	}

	msg := fmt.Sprintf(`

icmp_dest: %s
icmpDestination: %s

`, icmp_dest, *icmpDestination)
	fmt.Println(msg)

	pingMessage, ping_err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   int(w.IcmpID),
			Seq:  int(w.IcmpSequenceID),
			Data: []byte(w.IcmpMessage),
		},
	}).Marshal(nil)
	Fatal(ping_err)

	pingHeader, ping_header_err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(pingMessage),
		Protocol: 1, // ICMP
		TTL:      int(w.IcmpTTL),
		Src:      w.ClientAddress,
		Dst:      icmp_dest,
	}).Marshal()
	Fatal(ping_header_err)

	//	pp.Print(pingHeader)

	binary.BigEndian.PutUint16(pingHeader[2:], uint16(ipv4.HeaderLen+len(pingMessage))) // fix the length endianness on BSDs
	pingData := append(append(pingHeader, pingMessage...), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(pingData[10:], ipChecksum(pingData))
	pingPacket := make([]byte, 16)
	pingPacket[0] = 4                                               // Type: Data
	pingPacket[1] = 0                                               // Reserved
	pingPacket[2] = 0                                               // Reserved
	pingPacket[3] = 0                                               // Reserved
	binary.LittleEndian.PutUint32(pingPacket[4:], w.TheirIndex)     // Their index
	binary.LittleEndian.PutUint64(pingPacket[8:], 0)                // Nonce
	pingPacket, _ = w.SendCipher.Encrypt(pingPacket, nil, pingData) // Payload data
	if _, err := w.Connection.Write(pingPacket); err != nil {
		log.Fatalf("error writing ping message: %s", err)
	}
}
