package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	DEFAULT_CHECK_MODE = ``
)

var (
	checkMode = kingpin.Flag("check-mode", "Check MMode").Default(fmt.Sprintf("%s", DEFAULT_CHECK_MODE)).String()
)
