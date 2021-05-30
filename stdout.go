package main

import "github.com/k0kubun/pp"

func Debug(name string, obj interface{}) {
	if !debug_mode_enabled() {
		return
	}
	pp.Print(obj)
}
