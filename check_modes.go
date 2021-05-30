package main

import (
	"fmt"
	"os"

	"github.com/olorin/nagiosplugin"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	DEFAULT_CHECK_MODE = `icmp`
)

var (
	checkMode = kingpin.Flag("check-mode", "Check Mode").Short('m').Default(fmt.Sprintf("%s", DEFAULT_CHECK_MODE)).String()
)

func handle_check_mode() {
	switch *checkMode {
	case `icmp`:
		go check_wireguard_icmp()
	default:
		fmt.Printf("Invalid Mode %s\n", *checkMode)
		os.Exit(1)
	}
}

func GenerateTimedoutNagiosPluginsResult() (result *NagiosPluginResult) {
	crit_msg := fmt.Sprintf("Timed out after %dms", *timeout)
	result = &NagiosPluginResult{
		Status:  nagiosplugin.CRITICAL,
		Message: crit_msg,
	}
	return

}
