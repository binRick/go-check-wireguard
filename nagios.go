package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/binrick/go-check-wireguard/types"
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
	msg_prefix := fmt.Sprintf("Validated Wireguard Server %s using mode %s containing %d stages at %s://%s:%d in %dms", w.Host,
		strings.ToUpper(*checkMode),
		len(w.CheckStageResults), w.Proto, w.HostAddress, w.Port, time.Since(w.Started).Milliseconds())
	check_msg := fmt.Sprintf("CheckDestinationHost: %s:%d", w.CheckDestinationHost, w.CheckDestinationPort)

	ok_msg := fmt.Sprintf("%s %s", msg_prefix, check_msg)

	return ok_msg
}

func (w *WireguardClient) GenerateOKNagiosPluginResult() (result types.NagiosPluginResult) {
	result = types.NagiosPluginResult{
		Status:  nagiosplugin.OK,
		Message: w.GenerateOKMessage(),
	}
	return

}

//type WireguardClientAndNagiosPluginResult types.WireguardClientAndNagiosPluginResult

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

	res := types.NagiosPluginResult{
		Status:  nagiosplugin.CRITICAL,
		Message: crit_msg,
	}

	wgc.NagiosPluginResult = &res

	return &WireguardClientAndNagiosPluginResult{
		Wgc: wgc,
	}

}

func GenerateTimedoutNagiosPluginsResult() *WireguardClientAndNagiosPluginResult {
	crit_msg := fmt.Sprintf("Wireguard Server %s:%d Timed out after %dms while executing stage %s (#%d) %s with %d errors", *wgHost, *wgPort, *timeout,
		wgc.GetLatestStageResultName(),
		len(wgc.CheckStageResults),
		strings.ToUpper(*checkMode),
		len(wgc.Errors),
	)
	res := types.NagiosPluginResult{
		Status:  nagiosplugin.CRITICAL,
		Message: crit_msg,
	}
	wgc.NagiosPluginResult = &res

	ret := WireguardClientAndNagiosPluginResult{
		Wgc: wgc,
	}
	return &ret

}
