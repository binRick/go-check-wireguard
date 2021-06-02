package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/binrick/go-check-wireguard/types"
)

func HandleDecodeKeyFailure(failed_key_name string, key []byte, err error) {
	if err == nil {
		return
	}
	msg := fmt.Errorf(`CRITICAL: Failed to decode %d byte %s: %s`, len(key), failed_key_name, err)
	fmt.Println(msg)
	os.Exit(1)
	Fatal(msg)
}

func (w *WireguardClient) DecodeKeys() (bool, interface{}, error) {
	w.DecodeStarted = time.Now()
	decoded_keys := types.DecodedKeys{}
	client_private_key, client_private_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ClientPriv)
	HandleDecodeKeyFailure(`Client Private Key`, client_private_key, client_private_err)
	decoded_keys.ClientPriv = client_private_key

	ourPublic, client_public_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ClientPub)
	HandleDecodeKeyFailure(`Client Public Key`, ourPublic, client_public_err)
	decoded_keys.ClientPub = ourPublic

	theirPublic, server_public_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ServerPub)
	HandleDecodeKeyFailure(`Server Public Key`, ourPublic, server_public_err)
	decoded_keys.ServerPub = theirPublic

	preshared, preshared_err := base64.StdEncoding.DecodeString(w.EncodedKeys.PreShared)
	HandleDecodeKeyFailure(`Pre Shared Key`, preshared, preshared_err)
	decoded_keys.PreShared = preshared

	w.DecodedKeys = &decoded_keys

	w.DecodeDuration = time.Since(w.DecodeStarted)
	return true, ``, nil
}
