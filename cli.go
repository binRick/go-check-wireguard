package main

import (
	"time"
)

func exec_cli() {
	parse_args()

	go handle_check_mode()

	select {
	case plugin_result := <-plugin_result_channel:
		result = &plugin_result
	case <-time.After(time.Duration(1*(*timeout)) * time.Millisecond):
		result = GenerateTimedoutNagiosPluginsResult()
	}

	nag.AddResult(result.Status, result.Message)
	nag.Finish()
}
