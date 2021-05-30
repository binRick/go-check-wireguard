package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	DEFAULT_CHECK_MODE = `icmp`
)

var (
	checkMode                       = kingpin.Flag("check-mode", "Check Mode").Short('m').Default(fmt.Sprintf("%s", DEFAULT_CHECK_MODE)).OverrideDefaultFromEnvar(`CHECK_MODE`).String()
	enablePerformanceOutput         = kingpin.Flag("enable-performance-output", "Enable Performance Output").Short('P').Default(fmt.Sprintf("%v", false)).Bool()
	enableEnhancedPerformanceOutput = kingpin.Flag("enable-enhanced-performance-output", "Enable Enhanced Performance Output").Short('E').Default(fmt.Sprintf("%v", false)).Bool()
)
