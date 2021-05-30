package main

import (
	"time"
)

func get_exec_timeout() (dur time.Duration) {
	dur = (time.Duration(1*(*timeout)) * time.Millisecond)
	return
}

func exec_cli() {
	parse_args()

	go handle_check_mode()

	select {
	case plugin_result := <-plugin_result_channel:
		wgcResult = &plugin_result
	case <-time.After(get_exec_timeout()):
		wgcResult = GenerateTimedoutNagiosPluginsResult()
	}

	nag.AddResult(wgcResult.result.Status, wgcResult.result.Message)

	//	Debug(`wgc.CheckStageResults`, wgc.CheckStageResults)

	nag.Finish()
}
