package main

import (
	"log"
	"net"
	"time"
)

func (w *WireguardClient) ParseHostAddress() {
	hostAddress := ``
	parsed_host := net.ParseIP(*wgHost)
	w.LookupStarted = time.Now()
	if parsed_host == nil {
		a_rec, err := net.LookupHost(*wgHost)
		if err != nil || len(a_rec) < 1 {
			log.Fatalf(`lookup err: %s`, err)
		}
		hostAddress = a_rec[0]
		w.LookupsQty = len(a_rec)
	} else {
		hostAddress = *wgHost
	}
	w.HostAddress = net.ParseIP(hostAddress)
	w.LookupDuration = time.Since(w.LookupStarted)

	return
}
