package main

import "time"

func (w *WireguardClient) AddPerfData() {
	nag.AddPerfDatum("timeout", "ms", float64(*timeout))

	nag.AddPerfDatum("total_duration", "ms", float64(time.Since(w.Started).Milliseconds()))
	nag.AddPerfDatum("read_handshake_duration", "ms", float64(w.ReadHandshakeDuration.Milliseconds()))
	nag.AddPerfDatum("read_icmp_packet_duration", "ms", float64(w.ReadIcmpPacketDuration.Milliseconds()))
	nag.AddPerfDatum("decode_duration", "ms", float64(w.DecodeDuration.Milliseconds()))
	nag.AddPerfDatum("connect_duration", "ms", float64(w.ConnectionDuration.Milliseconds()))

	//nag.AddPerfDatum("lookup_dur", "ms", float64(lookup_dur.Milliseconds()))

	nag.AddPerfDatum("lookup_records", "", float64(lookup_records_qty))
	nag.AddPerfDatum("icmp_seq_id", "", float64(w.IcmpSequenceID))
	nag.AddPerfDatum("icmp_id", "", float64(w.IcmpID))
	nag.AddPerfDatum("icmp_req_message", "b", float64(len(w.IcmpMessage)))
	//nag.AddPerfDatum("icmp_echo_res_size", "b", float64(len(string(echo.Data))))
	//nag.AddPerfDatum("icmp_res_header_size", "b", float64(replyHeaderLen))

	nag.AddPerfDatum("wg_port", "", float64(w.Port))

	//nag.AddPerfDatum("test_icmp_packet", "b", float64(len(pingPacket)))
	//nag.AddPerfDatum("req_handshake_packet", "b", float64(len(initiationPacket)))
	//  nag.AddPerfDatum("res_handshake_packet", "b", float64(len(responsePacket)))

	nag.AddPerfDatum("started", "s", float64(w.Started.Unix()))
	nag.AddPerfDatum("ended", "s", float64(w.Ended.Unix()))
}
