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

	fmt.Printf("wgcResult.wgc.NagiosPluginResult=%s\n", wgcResult.wgc.NagiosPluginResult)

	if wgcResult.wgc.NagiosPluginResult != nil {
		nag.AddResult(wgcResult.wgc.NagiosPluginResult.Status, wgcResult.wgc.NagiosPluginResult.Message)
	}

	nag.Finish()
}
