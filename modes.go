package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	DEFAULT_CHECK_MODE = `icmp`
)

var (
	checkMode = kingpin.Flag("check-mode", "Check Mode").Short('m').Default(fmt.Sprintf("%s", DEFAULT_CHECK_MODE)).OverrideDefaultFromEnvar(`CHECK_MODE`).String()
)
