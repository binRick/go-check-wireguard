package main

import (
	"encoding/base64"
	"time"
)

func (w *WireguardClient) DecodeKeys() {
	w.DecodeStarted = time.Now()
	decoded_keys := DecodedKeys{}
	ourPrivate, client_private_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ClientPriv)
	Fatal(client_private_err)
	decoded_keys.ClientPriv = ourPrivate

	ourPublic, client_public_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ClientPub)
	Fatal(client_public_err)
	decoded_keys.ClientPub = ourPublic

	theirPublic, server_public_err := base64.StdEncoding.DecodeString(w.EncodedKeys.ServerPub)
	Fatal(server_public_err)
	decoded_keys.ServerPub = theirPublic

	preshared, preshared_err := base64.StdEncoding.DecodeString(w.EncodedKeys.PreShared)
	Fatal(preshared_err)
	decoded_keys.PreShared = preshared
	w.DecodedKeys = &decoded_keys
	w.DecodeDuration = time.Since(w.DecodeStarted)
	return
}
