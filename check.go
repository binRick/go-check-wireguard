package main

import (
	"fmt"
	"time"

	"github.com/olorin/nagiosplugin"
)

func check_wireguard() {
	wgc := NewWireguardClient()
	wgc.ParseHostAddress()
	wgc.DecodeKeys()
	wgc.PrepareHandshake()
	wgc.Connect()
	defer wgc.Close()
	wgc.WriteHandshake()
	wgc.ReadHandshakeResponse()
	wgc.WriteICMPPacket()
	wgc.ReadICMPPacket()
	wgc.Ended = time.Now()

	wgc.AddPerfData()

	ok_msg := fmt.Sprintf("Validated Wireguard Server %s at %s://%s:%d in %dms", wgc.Host, wgc.Proto, wgc.HostAddress, wgc.Port, time.Since(wgc.Started).Milliseconds())
	nag.AddResult(nagiosplugin.OK, ok_msg)
	nr := NagiosPluginResult{
		Status:  nagiosplugin.OK,
		Message: ok_msg,
	}
	plugin_result_channel <- nr
}
