package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/olorin/nagiosplugin"
)

func (w *WireguardClient) AddPerfData() {
	if !*enablePerformanceOutput {
		return
	}
	nag.AddPerfDatum("check_stage_results_qty", "", float64(len(w.CheckStageResults)))
	nag.AddPerfDatum("errors_qty", "", float64(len(w.Errors)))
	nag.AddPerfDatum("timeout", "ms", float64(*timeout))

	nag.AddPerfDatum("total_duration", "ms", float64(time.Since(w.Started).Milliseconds()))
	nag.AddPerfDatum("read_handshake_duration", "ms", float64(w.ReadHandshakeDuration.Milliseconds()))
	nag.AddPerfDatum("read_icmp_packet_duration", "ms", float64(w.ReadIcmpPacketDuration.Milliseconds()))
	nag.AddPerfDatum("decode_duration", "ms", float64(w.DecodeDuration.Milliseconds()))
	nag.AddPerfDatum("connect_duration", "ms", float64(w.ConnectionDuration.Milliseconds()))
	nag.AddPerfDatum("lookup_duration", "ms", float64(w.LookupDuration.Milliseconds()))

	nag.AddPerfDatum("lookup_records", "", float64(w.LookupsQty))

	nag.AddPerfDatum("debug_mode", "", float64(get_debug_mode_int()))
	nag.AddPerfDatum("icmp_seq_id", "", float64(w.IcmpSequenceID))
	nag.AddPerfDatum("icmp_id", "", float64(w.IcmpID))
	nag.AddPerfDatum("icmp_req_message", "b", float64(len(w.IcmpMessage)))

	nag.AddPerfDatum("wg_port", "", float64(w.Port))

	nag.AddPerfDatum("started", "s", float64(w.Started.Unix()))
	nag.AddPerfDatum("ended", "s", float64(w.Ended.Unix()))
}

func (w *WireguardClient) GenerateOKMessage() string {
	ok_msg := fmt.Sprintf("Validated Wireguard Server %s using mode %d %s stages at %s://%s:%d in %dms", w.Host, len(w.CheckStageResults), strings.ToUpper(*checkMode), w.Proto, w.HostAddress, w.Port, time.Since(w.Started).Milliseconds())
	return ok_msg
}

func (w *WireguardClient) GenerateOKNagiosPluginResult() (result NagiosPluginResult) {
	result = NagiosPluginResult{
		Status:  nagiosplugin.OK,
		Message: w.GenerateOKMessage(),
	}
	return

}

func GenerateCriticalNagiosPluginsResult() *WireguardClientAndNagiosPluginResult {
	crit_msg := fmt.Sprintf("Wireguard Server %s:%d Timed out after %dms while executing stage %s (#%d) %s with %d errors", *wgHost, *wgPort, *timeout,
		wgc.GetLatestStageResultName(),
		len(wgc.CheckStageResults),
		strings.ToUpper(*checkMode),
		len(wgc.Errors),
	)

	if len(wgc.Errors) > 0 {
		crit_msg = fmt.Sprintf(`%s: "%s"`,
			crit_msg,
			wgc.ErrorsAsLine(),
		)
	}

	res := &NagiosPluginResult{
		Status:  nagiosplugin.CRITICAL,
		Message: crit_msg,
	}

	return &WireguardClientAndNagiosPluginResult{
		wgc:    wgc,
		result: res,
	}

}
func GenerateTimedoutNagiosPluginsResult() *WireguardClientAndNagiosPluginResult {
	crit_msg := fmt.Sprintf("Wireguard Server %s:%d Timed out after %dms while executing stage %s (#%d) %s with %d errors", *wgHost, *wgPort, *timeout,
		wgc.GetLatestStageResultName(),
		len(wgc.CheckStageResults),
		strings.ToUpper(*checkMode),
		len(wgc.Errors),
	)
	res := &NagiosPluginResult{
		Status:  nagiosplugin.CRITICAL,
		Message: crit_msg,
	}

	ret := WireguardClientAndNagiosPluginResult{
		wgc:    wgc,
		result: res,
	}
	return &ret

}
