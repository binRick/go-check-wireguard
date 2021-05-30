package main

import (
	"fmt"
	"time"

	"github.com/olorin/nagiosplugin"
	"gopkg.in/alecthomas/kingpin.v2"
)

func exec_cli() {
	kingpin.HelpFlag.Short('h')
	kingpin.CommandLine.DefaultEnvars()
	kingpin.Parse()

	go check_wireguard()

	select {
	case plugin_result := <-plugin_result_channel:
		result = &plugin_result
	case <-time.After(time.Duration(1*(*timeout)) * time.Millisecond):
		crit_msg := fmt.Sprintf("Timed out after %dms", *timeout)
		result = &NagiosPluginResult{
			Status:  nagiosplugin.CRITICAL,
			Message: crit_msg,
		}
	}
	nag.AddResult(result.Status, result.Message)
	nag.Finish()
}
