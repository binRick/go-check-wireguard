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
		result = &plugin_result
	case <-time.After(get_exec_timeout()):
		result = GenerateTimedoutNagiosPluginsResult()
	}

	nag.AddResult(result.result.Status, result.result.Message)
	//pp.Print(wgc.CheckStageResults)
	nag.Finish()
}
