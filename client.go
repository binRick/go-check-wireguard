package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

//type WireguardClient types.WireguardClient

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

func (w *WireguardClient) IsFailed() bool {
	return (len(w.FailedCheckStageResults) > 0)
}

func (w *WireguardClient) PostFunction() (bool, interface{}, error) {
	w.Ended = time.Now()
	w.AddPerfData()
	return true, ``, nil
}

func (w *WireguardClient) Close() {
	if w.Connected {
		defer w.Connection.Close()
	}
}

func (w *WireguardClient) ErrorsAsLine() string {
	l := ``
	for _, e := range w.Errors {
		if len(l) > 0 {
			l = fmt.Sprintf(`%s, %s`, l, e)
		} else {
			l = fmt.Sprintf(`%s`, e)
		}
	}
	return l
}

func (w *WireguardClient) Connect() (bool, interface{}, error) {
	w.ConnectionStarted = time.Now()
	conn, err := net.Dial(w.Proto, fmt.Sprintf("%s:%d", w.HostAddress, w.Port))
	if err != nil {
		return false, ``, err
		log.Fatalf("error dialing udp socket: %s", err)
	}
	w.ConnectionDuration = time.Since(w.ConnectionStarted)
	w.Connection = conn
	w.Connected = true
	return true, ``, nil
}
