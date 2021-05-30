package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	timeout = kingpin.Flag("timeout", "Timeout (ms)").OverrideDefaultFromEnvar(`CHECK_TIMEOUT`).Default(fmt.Sprintf("%d", DEFAULT_TIMEOUT)).Short('t').Int()

	debugMode = kingpin.Flag("enable-debug-mode", "Enable Debug Mode").Default(fmt.Sprintf("%v", false)).OverrideDefaultFromEnvar(`DEBUG_MODE`).Short('d').Bool()
	wgHost    = kingpin.Flag("host", "Wireguard Server Host").Default(fmt.Sprintf("%s", DEFAULT_WG_HOST)).OverrideDefaultFromEnvar(`WIREGUARD_SERVER`).Short('H').String()
	wgPort    = kingpin.Flag("port", "Wireguard Server Port").Default(fmt.Sprintf("%d", DEFAULT_WG_PORT)).Short('p').Int()
	wgProto   = kingpin.Flag("proto", "Wireguard Server Protocol").Default(fmt.Sprintf("%s", DEFAULT_WG_PROTO)).String()

	icmpMessage    = kingpin.Flag("icmp-message", "ICMP Packet Message").Default(fmt.Sprintf("%s", DEFAULT_ICMP_MESSAGE)).String()
	icmpTTL        = kingpin.Flag("icmp-ttl", "ICMP Packet TTL").Default(fmt.Sprintf("%d", DEFAULT_ICMP_TTL)).Int()
	icmpSequenceID = kingpin.Flag("icmp-seq", "ICMP Packet TCP Sequence ID").Default(fmt.Sprintf("%d", DEFAULT_ICMP_SEQUENCE_ID)).Int()
	icmpID         = kingpin.Flag("icmp-id", "ICMP Packet TCP ID").Default(fmt.Sprintf("%d", DEFAULT_ICMP_ID)).Int()

	wgClientAddress = kingpin.Flag("client-address", "Wireguard Client Address").Default(fmt.Sprintf("%s", DEFAULT_WG_CLIENT_ADDRESS)).OverrideDefaultFromEnvar(`CLIENT_ADDRESS`).IP()
	wgServerAddress = kingpin.Flag("server-address", "Wireguard Server Address").Default(fmt.Sprintf("%s", DEFAULT_WG_SERVER_ADDRESS)).OverrideDefaultFromEnvar(`SERVER_ADDRESS`).IP()

	serverPub  = kingpin.Flag("server-pub", "Wireguard Server Public Key").Default(fmt.Sprintf("%s", DEFAULT_SERVER_PUB_KEY)).OverrideDefaultFromEnvar(`SERVER_PUBLIC_KEY`).String()
	clientPub  = kingpin.Flag("client-pub", "Wireguard Client Public Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PUB_KEY)).OverrideDefaultFromEnvar(`CLIENT_PUBLIC_KEY`).String()
	clientPriv = kingpin.Flag("client-priv", "Wireguard Client Private Key").Default(fmt.Sprintf("%s", DEFAULT_CLIENT_PRIV_KEY)).OverrideDefaultFromEnvar(`CLIENT_PRIVATE_KEY`).String()
	preShared  = kingpin.Flag("pre-shared", "Wireguard Pre Shared Key").Default(fmt.Sprintf("%s", DEFAULT_PRESHARED_KEY)).OverrideDefaultFromEnvar(`PRESHARED_KEY`).String()
)

func parse_args() {
	kingpin.HelpFlag.Short('h')
	kingpin.CommandLine.DefaultEnvars()
	kingpin.Parse()
}

func debug_mode_enabled() bool {
	if *debugMode {
		return true
	}
	return false
}

func get_debug_mode_int() int {
	if debug_mode_enabled() {
		return 1
	}
	return 0
}
