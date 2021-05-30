package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
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

	serverPub  = kingpin.Flag("server-pub", "Wireguard Server Public Key").Default(fmt.Sprintf("%s", DEFAULT_SERVER_PUB_KEY)).String()
	clientPub  = kingpin.Flag("client-pub", "Wireguard Client Public Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PUB_KEY)).String()
	clientPriv = kingpin.Flag("client-priv", "Wireguard Client Private Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PRIV_KEY)).String()
	preShared  = kingpin.Flag("pre-shared", "Wireguard Pre Shared Key").Default(fmt.Sprintf("%s", DEFAULT_PRESHARED_KEY)).String()
)
