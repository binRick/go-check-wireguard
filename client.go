package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func (w *WireguardClient) Close() {
	w.Connection.Close()
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
