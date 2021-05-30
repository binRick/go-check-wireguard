package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/olorin/nagiosplugin"
)

func (w *WireguardClient) AddPerfData() {
	nag.AddPerfDatum("timeout", "ms", float64(*timeout))

	nag.AddPerfDatum("total_duration", "ms", float64(time.Since(w.Started).Milliseconds()))
	nag.AddPerfDatum("read_handshake_duration", "ms", float64(w.ReadHandshakeDuration.Milliseconds()))
	nag.AddPerfDatum("read_icmp_packet_duration", "ms", float64(w.ReadIcmpPacketDuration.Milliseconds()))
	nag.AddPerfDatum("decode_duration", "ms", float64(w.DecodeDuration.Milliseconds()))
	nag.AddPerfDatum("connect_duration", "ms", float64(w.ConnectionDuration.Milliseconds()))
	nag.AddPerfDatum("lookup_duration", "ms", float64(w.LookupDuration.Milliseconds()))

	nag.AddPerfDatum("lookup_records", "", float64(w.LookupsQty))

	nag.AddPerfDatum("icmp_seq_id", "", float64(w.IcmpSequenceID))
	nag.AddPerfDatum("icmp_id", "", float64(w.IcmpID))
	nag.AddPerfDatum("icmp_req_message", "b", float64(len(w.IcmpMessage)))

	nag.AddPerfDatum("wg_port", "", float64(w.Port))

	nag.AddPerfDatum("started", "s", float64(w.Started.Unix()))
	nag.AddPerfDatum("ended", "s", float64(w.Ended.Unix()))
}

func (w *WireguardClient) GenerateOKMessage() string {
	ok_msg := fmt.Sprintf("Validated Wireguard Server %s using mode %s at %s://%s:%d in %dms", w.Host, strings.ToUpper(*checkMode), w.Proto, w.HostAddress, w.Port, time.Since(w.Started).Milliseconds())
	nag.AddResult(nagiosplugin.OK, ok_msg)
	return ok_msg
}

func (w *WireguardClient) GenerateOKNagiosPluginResult() NagiosPluginResult {
	nr := NagiosPluginResult{
		Status:  nagiosplugin.OK,
		Message: w.GenerateOKMessage(),
	}
	return nr

}
