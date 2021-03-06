package main

import (
	"fmt"
	"os"
	"time"

	"github.com/binrick/go-check-wireguard/types"
)

var (
	wgc *WireguardClient
)

func (w *WireguardClient) HandleStageExecution(name string, fxn func() (bool, interface{}, error)) {
	//	if w.IsFailed() {
	//		return
	//	}
	started := time.Now()
	success, res, err := fxn()
	if err != nil {
		success = false
	}
	dur := time.Since(started)
	csr := types.CheckStageResult{
		Name:     name,
		Started:  started,
		Duration: dur,
		Success:  success,
		Function: fmt.Sprintf(`%s`, fxn),
		Result:   res,
		Error:    err,
	}
	if !csr.Success {
		w.FailedCheckStageResults = append(w.FailedCheckStageResults, csr)
		if err != nil {
			w.Errors = append(w.Errors, err)
		}
		res := GenerateCriticalNagiosPluginsResult()
		nag.AddResult(res.Result.Status, res.Result.Message)
		nag.Finish()
	} else {
		w.CheckStageResults = append(w.CheckStageResults, csr)
	}
}

//type WireguardClientAndNagiosPluginResult types.WireguardClientAndNagiosPluginResult
//type WireguardClient types.WireguardClient

func handle_check_mode() {
	wgc = NewWireguardClient()
	defer wgc.Close()
	wgc.HandleStageExecution(`ParseHostAddress`, wgc.ParseHostAddress)
	wgc.HandleStageExecution(`DecodeKeys`, wgc.DecodeKeys)
	wgc.HandleStageExecution(`PrepareHandshake`, wgc.PrepareHandshake)
	wgc.HandleStageExecution(`Connect`, wgc.Connect)
	wgc.HandleStageExecution(`WriteHandshake`, wgc.WriteHandshake)
	wgc.HandleStageExecution(`ReadHandshakeResponse`, wgc.ReadHandshakeResponse)

	switch *checkMode {
	case `dns`:
		wgc.HandleStageExecution(*checkMode, wgc.CheckDns)
	case `icmp`:
		wgc.HandleStageExecution(*checkMode, wgc.CheckIcmp)
	default:
		fmt.Printf("Invalid Mode %s\n", *checkMode)
		os.Exit(1)
	}

	wgc.HandleStageExecution(`PostFunction`, wgc.PostFunction)

	res := wgc.GenerateOKNagiosPluginResult()

	wgc.NagiosPluginResult = &res
	ret := WireguardClientAndNagiosPluginResult{
		Wgc: wgc,
	}
	plugin_result_channel <- ret
}
