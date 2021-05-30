package main

import (
	"fmt"
	"os"
	"time"
)

func (w *WireguardClient) CheckIcmpOneOneOneOne() {
	w.WriteICMPPacket1()
	w.ReadICMPPacket1()
	return
}

func (w *WireguardClient) CheckIcmp() {
	w.WriteICMPPacket()
	w.ReadICMPPacket()
	return
}

func handle_check_mode() {
	wgc := NewWireguardClient()
	wgc.ParseHostAddress()
	wgc.DecodeKeys()
	wgc.PrepareHandshake()
	wgc.Connect()
	defer wgc.Close()
	wgc.WriteHandshake()
	wgc.ReadHandshakeResponse()

	switch *checkMode {
	case `icmp`:
		wgc.CheckIcmp()
	case `1`:
		wgc.CheckIcmpOneOneOneOne()
	default:
		fmt.Printf("Invalid Mode %s\n", *checkMode)
		os.Exit(1)
	}

	wgc.Ended = time.Now()

	wgc.AddPerfData()

	plugin_result_channel <- wgc.GenerateOKNagiosPluginResult()
}
