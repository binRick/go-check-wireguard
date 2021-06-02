package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"time"

	"github.com/binrick/go-check-wireguard/types"
	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
)

func (w *WireguardClient) ReadHandshakeResponse() (bool, interface{}, error) {
	w.ReadHandshakeStarted = time.Now()
	responsePacket := make([]byte, 92)
	n, err := w.Connection.Read(responsePacket)
	w.ReadHandshakeDuration = time.Since(w.ReadHandshakeStarted)
	if err != nil {
		log.Fatalf("error reading response packet: %s", err)
	}
	if n != len(responsePacket) {
		log.Fatalf("response packet too short: want %d, got %d", len(responsePacket), n)
	}

	if responsePacket[0] != 2 { // Type: Response
		log.Fatalf("response packet type wrong: want %d, got %d", 2, responsePacket[0])
	}
	if responsePacket[1] != 0 || responsePacket[2] != 0 || responsePacket[3] != 0 {
		log.Fatalf("response packet has non-zero reserved fields")
	}
	theirIndex := binary.LittleEndian.Uint32(responsePacket[4:])
	w.TheirIndex = theirIndex
	ourIndex := binary.LittleEndian.Uint32(responsePacket[8:])
	w.OurIndex = ourIndex
	if ourIndex != 28 {
		log.Fatalf("response packet index wrong: want %d, got %d", 28, ourIndex)
	}
	payload, sendCipher, receiveCipher, err := w.Handshake.Hs.ReadMessage(nil, responsePacket[12:60])
	if err != nil {
		log.Fatalf("error reading handshake message: %s", err)
	}
	w.SendCipher = sendCipher
	w.ReceiveCipher = receiveCipher
	if len(payload) > 0 {
		log.Fatalf("unexpected payload: %x", payload)
	}

	return true, ``, nil
}

func (w *WireguardClient) WriteHandshake() (bool, interface{}, error) {
	now := time.Now()
	tai64n := make([]byte, 12)
	binary.BigEndian.PutUint64(tai64n[:], 4611686018427387914+uint64(now.Unix()))
	binary.BigEndian.PutUint32(tai64n[8:], uint32(now.Nanosecond()))
	initiationPacket := make([]byte, 8)
	initiationPacket[0] = 1                                 // Type: Initiation
	initiationPacket[1] = 0                                 // Reserved
	initiationPacket[2] = 0                                 // Reserved
	initiationPacket[3] = 0                                 // Reserved
	binary.LittleEndian.PutUint32(initiationPacket[4:], 28) // Sender index: 28 (arbitrary)
	initiationPacket, _, _, _ = w.Handshake.Hs.WriteMessage(initiationPacket, tai64n)
	hasher, _ := blake2s.New256(nil)
	hasher.Write([]byte("mac1----"))
	hasher.Write(w.DecodedKeys.ServerPub)
	hasher, _ = blake2s.New128(hasher.Sum(nil))
	hasher.Write(initiationPacket)
	initiationPacket = append(initiationPacket, hasher.Sum(nil)[:16]...)
	initiationPacket = append(initiationPacket, make([]byte, 16)...)
	if _, err := w.Connection.Write(initiationPacket); err != nil {
		log.Fatalf("error writing initiation packet: %s", err)
	}
	return true, ``, nil
}

func (w *WireguardClient) PrepareHandshake() (bool, interface{}, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, hs_err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Random:                rand.Reader,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              []byte(DEFAULT_WG_PROTOCOL_PROLOG),
		PresharedKey:          w.DecodedKeys.PreShared,
		PresharedKeyPlacement: 2,
		StaticKeypair:         noise.DHKey{Private: w.DecodedKeys.ClientPriv, Public: w.DecodedKeys.ClientPub},
		PeerStatic:            w.DecodedKeys.ServerPub,
	})
	if hs_err != nil {
		return false, ``, hs_err
	}

	w.Handshake = &types.Handshake{
		Hs: hs,
		Cs: &cs,
	}

	return true, ``, hs_err
}
