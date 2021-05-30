package main

import (
	"fmt"
	"net"
	"time"
)

func (w *WireguardClient) ParseHostAddress() (bool, interface{}, error) {
	hostAddress := ``
	parsed_host := net.ParseIP(*wgHost)
	w.LookupStarted = time.Now()
	if parsed_host == nil {
		a_rec, err := net.LookupHost(*wgHost)
		if err != nil {
			err = fmt.Errorf(`DNS Lookup error for domain %s: %s`, *wgHost, err)
			return false, ``, err
		}
		if len(a_rec) < 1 {
			err = fmt.Errorf(`DNS Lookup for domain %s returned no results`)
			return false, ``, err
		}
		hostAddress = a_rec[0]
		w.LookupsQty = len(a_rec)
	} else {
		hostAddress = *wgHost
	}
	w.HostAddress = net.ParseIP(hostAddress)
	w.LookupDuration = time.Since(w.LookupStarted)

	return true, w.HostAddress, nil
}
