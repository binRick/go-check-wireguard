package main

import (
	"fmt"
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

	if false {
		fmt.Printf("wgcResult.Wgc.NagiosPluginResult=%s\n", wgcResult.Wgc.NagiosPluginResult)
	}

	if wgcResult.Wgc.NagiosPluginResult != nil {
		nag.AddResult(wgcResult.Wgc.NagiosPluginResult.Status, wgcResult.Wgc.NagiosPluginResult.Message)
	}

	nag.Finish()
}
