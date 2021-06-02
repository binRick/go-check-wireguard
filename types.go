package main

import (
	"net"
	"time"

	"github.com/binrick/go-check-wireguard/types"
	"github.com/flynn/noise"
)

type WireguardClient struct {
	Host        string
	HostAddress net.IP
	Port        int
	Proto       string
	Started     time.Time
	Ended       time.Time

	IcmpMessage    string
	IcmpTTL        int
	IcmpSequenceID int
	IcmpID         int

	CheckDestinationHost net.IP
	CheckDestinationPort int

	ClientAddress net.IP
	ServerAddress net.IP

	EncodedKeys *types.EncodedKeys
	DecodedKeys *types.DecodedKeys

	Handshake *types.Handshake

	Connection net.Conn

	ConnectionDuration time.Duration
	ConnectionStarted  time.Time

	DecodeStarted  time.Time
	DecodeDuration time.Duration

	ReadPacketStarted  time.Time
	ReadPacketDuration time.Duration

	ReadHandshakeStarted  time.Time
	ReadHandshakeDuration time.Duration

	LookupStarted  time.Time
	LookupDuration time.Duration

	LookupsQty int

	ReadIcmpPacketStarted  time.Time
	ReadIcmpPacketDuration time.Duration

	TheirIndex uint32
	OurIndex   uint32

	SendCipher    *noise.CipherState
	ReceiveCipher *noise.CipherState

	CompletedCheckStages    []string
	CheckStageResults       []types.CheckStageResult
	FailedCheckStageResults []types.CheckStageResult

	NagiosPluginResult *types.NagiosPluginResult
	DebugMode          bool

	Connected bool

	Errors []error
}
type WireguardClientAndNagiosPluginResult struct {
	Wgc    *WireguardClient
	Result *types.NagiosPluginResult
}
