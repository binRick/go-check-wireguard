package main

import (
	"github.com/olorin/nagiosplugin"
)

const (
	DEFAULT_SERVER_PUB_KEY     = `qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=`
	DEFAULT_CLIENT_PUB_KEY     = `K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=`
	DEFAULT_PRESHARED_KEY      = `FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=`
	DEFAULT_CLIENT_PRIV_KEY    = `WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=`
	DEFAULT_WG_HOST            = `demo.wireguard.com`
	DEFAULT_WG_PORT            = 12913
	DEFAULT_WG_PROTO           = `udp`
	DEFAULT_ICMP_MESSAGE       = `WireGuard1`
	DEFAULT_WG_CLIENT_ADDRESS  = `10.189.129.2`
	DEFAULT_WG_SERVER_ADDRESS  = `10.189.129.1`
	DEFAULT_WG_CLIENT_NETMASK  = 29
	DEFAULT_ICMP_TTL           = 20
	DEFAULT_ICMP_SEQUENCE_ID   = 438
	DEFAULT_ICMP_ID            = 921
	DEFAULT_TIMEOUT            = 50
	DEFAULT_WG_PROTOCOL_PROLOG = `WireGuard v1 zx2c4 Jason@zx2c4.com`
	DEBUG_WGC_OBJECT           = false
)

type WireguardClientAndNagiosPluginResult struct {
	wgc    *WireguardClient
	result *NagiosPluginResult
}

var (
	nag                   = nagiosplugin.NewCheck()
	plugin_result_channel = make(chan WireguardClientAndNagiosPluginResult, 1)
	result                = &WireguardClientAndNagiosPluginResult{}
	lookup_records_qty    int
)

func main() {
	exec_cli()
}
