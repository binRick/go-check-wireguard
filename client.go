package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func NewWireguardClient() *WireguardClient {
	wgc := &WireguardClient{
		Started: time.Now(),
		Host:    *wgHost,
		Port:    *wgPort,
		EncodedKeys: &EncodedKeys{
			ClientPriv: *clientPriv,
			ServerPub:  *serverPub,
			PreShared:  *preShared,
			ClientPub:  *clientPub,
		},
		Proto:          *wgProto,
		IcmpMessage:    *icmpMessage,
		IcmpTTL:        *icmpTTL,
		IcmpID:         *icmpID,
		IcmpSequenceID: *icmpSequenceID,
		ClientAddress:  *wgClientAddress,
		ServerAddress:  *wgServerAddress,
		DebugMode:      debug_mode_enabled(),
	}
	return wgc

}

func (w *WireguardClient) PostFunction() {
	w.Ended = time.Now()
	w.AddPerfData()
}

func (w *WireguardClient) Close() {
	defer w.Connection.Close()
}

func (w *WireguardClient) Connect() {
	w.ConnectionStarted = time.Now()
	conn, err := net.Dial(w.Proto, fmt.Sprintf("%s:%d", w.HostAddress, w.Port))
	if err != nil {
		log.Fatalf("error dialing udp socket: %s", err)
	}
	w.ConnectionDuration = time.Since(w.ConnectionStarted)
	w.Connection = conn
}
