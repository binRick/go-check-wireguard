package main

import (
	"log"
	"net"
)

func (w *WireguardClient) ParseHostAddress() {
	hostAddress := ``
	parsed_host := net.ParseIP(*wgHost)
	//lookup_started := time.Now()
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
	w.HostAddress = net.ParseIP(hostAddress)

	return
}
