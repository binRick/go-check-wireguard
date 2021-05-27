package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/flynn/noise"
	"github.com/k0kubun/pp"
	"github.com/olorin/nagiosplugin"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gopkg.in/alecthomas/kingpin.v2"
)

type WireguardClient struct {
	Host        string
	HostAddress net.IP
	Port        int
	Proto       string

	ClientPub     string
	ClientPrivate string
	ServerPub     string
	PreShared     string

	IcmpMessage    string
	IcmpTTL        int
	IcmpSequenceID int
	IcmpID         int

	ClientAddress net.IP
	ServerAddress net.IP
}

type NagiosPluginResult struct {
	Status  nagiosplugin.Status
	Message string
}

const (
	DEFAULT_SERVER_PUB_KEY    = `qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=`
	DEFAULT_CLIENT_PUB_KEY    = `K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=`
	DEFAULT_PRESHARED_KEY     = `FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=`
	DEFAULT_CLIENT_PRIV_KEY   = `WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=`
	DEFAULT_WG_HOST           = `demo.wireguard.com`
	DEFAULT_WG_PORT           = 12913
	DEFAULT_WG_PROTO          = `udp`
	DEFAULT_ICMP_MESSAGE      = `WireGuard1`
	DEFAULT_WG_CLIENT_ADDRESS = `10.189.129.2`
	DEFAULT_WG_SERVER_ADDRESS = `10.189.129.1`
	DEFAULT_WG_CLIENT_NETMASK = 29
	DEFAULT_ICMP_TTL          = 20
	DEFAULT_ICMP_SEQUENCE_ID  = 438
	DEFAULT_ICMP_ID           = 921
	DEFAULT_TIMEOUT           = 500
	DEBUG_WGC_OBJECT          = false
)

var (
	timeout = kingpin.Flag("timeout", "Timeout (ms)").Default(fmt.Sprintf("%d", DEFAULT_TIMEOUT)).Int()

	wgHost  = kingpin.Flag("host", "Wireguard Server Host").Default(fmt.Sprintf("%s", DEFAULT_WG_HOST)).String()
	wgPort  = kingpin.Flag("port", "Wireguard Server Port").Default(fmt.Sprintf("%d", DEFAULT_WG_PORT)).Int()
	wgProto = kingpin.Flag("proto", "Wireguard Server Protocol").Default(fmt.Sprintf("%s", DEFAULT_WG_PROTO)).String()

	icmpMessage    = kingpin.Flag("icmp-message", "ICMP Packet Message").Default(fmt.Sprintf("%s", DEFAULT_ICMP_MESSAGE)).String()
	icmpTTL        = kingpin.Flag("icmp-ttl", "ICMP Packet TTL").Default(fmt.Sprintf("%d", DEFAULT_ICMP_TTL)).Int()
	icmpSequenceID = kingpin.Flag("icmp-seq", "ICMP Packet TCP Sequence ID").Default(fmt.Sprintf("%d", DEFAULT_ICMP_SEQUENCE_ID)).Int()
	icmpID         = kingpin.Flag("icmp-id", "ICMP Packet TCP ID").Default(fmt.Sprintf("%d", DEFAULT_ICMP_ID)).Int()

	wgClientAddress = kingpin.Flag("client-address", "Wireguard Client Address").Default(fmt.Sprintf("%s", DEFAULT_WG_CLIENT_ADDRESS)).IP()
	wgServerAddress = kingpin.Flag("server-address", "Wireguard Client Address").Default(fmt.Sprintf("%s", DEFAULT_WG_SERVER_ADDRESS)).IP()
	wgClientNetmask = kingpin.Flag("client-netmask", "Wireguard Client Address").Default(fmt.Sprintf("%d", DEFAULT_WG_CLIENT_NETMASK)).Int()

	serverPub  = kingpin.Flag("server-pub", "Wireguard Server Public Key").Default(fmt.Sprintf("%s", DEFAULT_SERVER_PUB_KEY)).String()
	clientPub  = kingpin.Flag("client-pub", "Wireguard Client Public Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PUB_KEY)).String()
	clientPriv = kingpin.Flag("client-priv", "Wireguard Client Private Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PRIV_KEY)).String()
	preShared  = kingpin.Flag("pre-shared", "Wireguard Pre Shared Key").Default(fmt.Sprintf("%s", DEFAULT_PRESHARED_KEY)).String()
)

var (
	nag                   = nagiosplugin.NewCheck()
	plugin_result_channel = make(chan NagiosPluginResult, 1)
	result                = &NagiosPluginResult{}
)

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.CommandLine.DefaultEnvars()
	kingpin.Parse()

	go check_wireguard()

	select {
	case plugin_result := <-plugin_result_channel:
		result = &plugin_result
	case <-time.After(time.Duration(1*(*timeout)) * time.Millisecond):
		crit_msg := fmt.Sprintf("Timed out after %dms", *timeout)
		result = &NagiosPluginResult{
			Status:  nagiosplugin.CRITICAL,
			Message: crit_msg,
		}
	}
	nag.AddResult(result.Status, result.Message)
	nag.Finish()
}

func check_wireguard() {
	hostAddress := ``
	lookup_records_qty := 0
	parsed_host := net.ParseIP(*wgHost)
	lookup_started := time.Now()
	if parsed_host == nil {
		a_rec, err := net.LookupHost(*wgHost)
		if err != nil || len(a_rec) < 1 {
			log.Fatalf(`lookup err: %s`, err)
		}
		hostAddress = a_rec[0]
		lookup_records_qty = len(a_rec)
	} else {
		hostAddress = *wgHost
	}
	lookup_dur := time.Since(lookup_started)

	wgc := WireguardClient{
		Host:           *wgHost,
		HostAddress:    net.ParseIP(hostAddress),
		Port:           *wgPort,
		ClientPub:      *clientPub,
		Proto:          *wgProto,
		ClientPrivate:  *clientPriv,
		ServerPub:      *serverPub,
		PreShared:      *preShared,
		IcmpMessage:    *icmpMessage,
		IcmpTTL:        *icmpTTL,
		IcmpID:         *icmpID,
		IcmpSequenceID: *icmpSequenceID,
		ClientAddress:  *wgClientAddress,
		ServerAddress:  *wgServerAddress,
	}

	if DEBUG_WGC_OBJECT {
		pp.Print(wgc)
	}

	started := time.Now()
	ourPrivate, client_private_err := base64.StdEncoding.DecodeString(wgc.ClientPrivate)
	Fatal(client_private_err)

	ourPublic, client_public_err := base64.StdEncoding.DecodeString(wgc.ClientPub)
	Fatal(client_public_err)

	theirPublic, server_public_err := base64.StdEncoding.DecodeString(wgc.ServerPub)
	Fatal(server_public_err)

	preshared, preshared_err := base64.StdEncoding.DecodeString(wgc.PreShared)
	Fatal(preshared_err)

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, hs_err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Random:                rand.Reader,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          preshared,
		PresharedKeyPlacement: 2,
		StaticKeypair:         noise.DHKey{Private: ourPrivate, Public: ourPublic},
		PeerStatic:            theirPublic,
	})
	Fatal(hs_err)

	dial_started := time.Now()
	conn, err := net.Dial(wgc.Proto, fmt.Sprintf("%s:%d", wgc.HostAddress, wgc.Port))
	dial_dur := time.Since(dial_started)
	if err != nil {
		log.Fatalf("error dialing udp socket: %s", err)
	}
	defer conn.Close()

	// write handshake initiation packet
	now := time.Now()
	tai64n := make([]byte, 12)
	binary.BigEndian.PutUint64(tai64n[:], 4611686018427387914+uint64(now.Unix()))
	binary.BigEndian.PutUint32(tai64n[8:], uint32(now.Nanosecond()))
	initiationPacket := make([]byte, 8)
	initiationPacket[0] = 1                                 // Type: Initiation
	initiationPacket[1] = 0                                 // Reserved
	initiationPacket[2] = 0                                 // Reserved
	initiationPacket[3] = 0                                 // Reserved
	binary.LittleEndian.PutUint32(initiationPacket[4:], 28) // Sender index: 28 (arbitrary)
	initiationPacket, _, _, _ = hs.WriteMessage(initiationPacket, tai64n)
	hasher, _ := blake2s.New256(nil)
	hasher.Write([]byte("mac1----"))
	hasher.Write(theirPublic)
	hasher, _ = blake2s.New128(hasher.Sum(nil))
	hasher.Write(initiationPacket)
	initiationPacket = append(initiationPacket, hasher.Sum(nil)[:16]...)
	initiationPacket = append(initiationPacket, make([]byte, 16)...)
	if _, err := conn.Write(initiationPacket); err != nil {
		log.Fatalf("error writing initiation packet: %s", err)
	}

	// read handshake response packet
	responsePacket := make([]byte, 92)
	res_started := time.Now()
	n, err := conn.Read(responsePacket)
	hs_dur := time.Since(res_started)
	if err != nil {
		log.Fatalf("error reading response packet: %s", err)
	}
	if n != len(responsePacket) {
		log.Fatalf("response packet too short: want %d, got %d", len(responsePacket), n)
	}
	//	fmt.Printf("Read %d byte response packet in %dms\n", len(responsePacket), time.Since(started).Milliseconds())
	if responsePacket[0] != 2 { // Type: Response
		log.Fatalf("response packet type wrong: want %d, got %d", 2, responsePacket[0])
	}
	if responsePacket[1] != 0 || responsePacket[2] != 0 || responsePacket[3] != 0 {
		log.Fatalf("response packet has non-zero reserved fields")
	}
	theirIndex := binary.LittleEndian.Uint32(responsePacket[4:])
	ourIndex := binary.LittleEndian.Uint32(responsePacket[8:])
	if ourIndex != 28 {
		log.Fatalf("response packet index wrong: want %d, got %d", 28, ourIndex)
	}
	payload, sendCipher, receiveCipher, err := hs.ReadMessage(nil, responsePacket[12:60])
	if err != nil {
		log.Fatalf("error reading handshake message: %s", err)
	}
	if len(payload) > 0 {
		log.Fatalf("unexpected payload: %x", payload)
	}

	// write ICMP Echo packet
	pingMessage, ping_err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   int(wgc.IcmpID),
			Seq:  int(wgc.IcmpSequenceID),
			Data: []byte(wgc.IcmpMessage),
		},
	}).Marshal(nil)
	Fatal(ping_err)

	pingHeader, ping_header_err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(pingMessage),
		Protocol: 1, // ICMP
		TTL:      int(wgc.IcmpTTL),
		Src:      wgc.ClientAddress,
		Dst:      wgc.ServerAddress,
	}).Marshal()
	Fatal(ping_header_err)

	binary.BigEndian.PutUint16(pingHeader[2:], uint16(ipv4.HeaderLen+len(pingMessage))) // fix the length endianness on BSDs
	pingData := append(append(pingHeader, pingMessage...), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(pingData[10:], ipChecksum(pingData))
	pingPacket := make([]byte, 16)
	pingPacket[0] = 4                                             // Type: Data
	pingPacket[1] = 0                                             // Reserved
	pingPacket[2] = 0                                             // Reserved
	pingPacket[3] = 0                                             // Reserved
	binary.LittleEndian.PutUint32(pingPacket[4:], theirIndex)     // Their index
	binary.LittleEndian.PutUint64(pingPacket[8:], 0)              // Nonce
	pingPacket, _ = sendCipher.Encrypt(pingPacket, nil, pingData) // Payload data
	if _, err := conn.Write(pingPacket); err != nil {
		log.Fatalf("error writing ping message: %s", err)
	}
	//	fmt.Printf("Wrote %d byte ICMP packet in %dms\n", len(pingPacket), time.Since(started).Milliseconds())

	// read ICMP Echo Reply packet
	replyPacket := make([]byte, 80)
	icmp_started := time.Now()
	n, err = conn.Read(replyPacket)
	icmp_dur := time.Since(icmp_started)
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
	replyPacket, err = receiveCipher.Decrypt(nil, nil, replyPacket[16:])
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

	if echo.ID != wgc.IcmpID || echo.Seq != wgc.IcmpSequenceID || string(echo.Data) != wgc.IcmpMessage {
		log.Fatalf("incorrect echo response: %#v", echo)
	}
	ended := time.Now()

	nag.AddPerfDatum("total_duration", "ms", float64(time.Since(started).Milliseconds()))
	nag.AddPerfDatum("dial_duration", "ms", float64(dial_dur.Milliseconds()))
	nag.AddPerfDatum("icmp_duration", "ms", float64(icmp_dur.Milliseconds()))
	nag.AddPerfDatum("lookup_dur", "ms", float64(lookup_dur.Milliseconds()))
	nag.AddPerfDatum("handshake_duration", "ms", float64(hs_dur.Milliseconds()))
	nag.AddPerfDatum("timeout", "ms", float64(*timeout))

	nag.AddPerfDatum("lookup_records", "", float64(lookup_records_qty))
	nag.AddPerfDatum("icmp_seq_id", "", float64(wgc.IcmpSequenceID))
	nag.AddPerfDatum("icmp_id", "", float64(wgc.IcmpID))
	nag.AddPerfDatum("icmp_req_message", "b", float64(len(wgc.IcmpMessage)))
	nag.AddPerfDatum("icmp_echo_res_size", "b", float64(len(string(echo.Data))))
	nag.AddPerfDatum("icmp_res_header_size", "b", float64(replyHeaderLen))

	nag.AddPerfDatum("wg_port", "", float64(wgc.Port))
	nag.AddPerfDatum("wg_client_netmask", "", float64(*wgClientNetmask))

	nag.AddPerfDatum("test_icmp_packet", "b", float64(len(pingPacket)))
	nag.AddPerfDatum("req_handshake_packet", "b", float64(len(initiationPacket)))
	nag.AddPerfDatum("res_handshake_packet", "b", float64(len(responsePacket)))

	nag.AddPerfDatum("started", "s", float64(started.Unix()))
	nag.AddPerfDatum("ended", "s", float64(ended.Unix()))

	ok_msg := fmt.Sprintf("Validated Wireguard Server %s at %s://%s:%d in %dms", wgc.Host, wgc.Proto, wgc.HostAddress, wgc.Port, time.Since(started).Milliseconds())
	nag.AddResult(nagiosplugin.OK, ok_msg)
	nr := NagiosPluginResult{
		Status:  nagiosplugin.OK,
		Message: ok_msg,
	}
	plugin_result_channel <- nr
}

func get_hash(in string) string {
	hash := md5.Sum([]byte(fmt.Sprintf(`%s`, in)))
	h := hex.EncodeToString(hash[:])[0:16]
	return h
}

func ipChecksum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

func Fatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
