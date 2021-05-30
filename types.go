package main

import (
	"net"
	"time"

	"github.com/flynn/noise"
	"github.com/olorin/nagiosplugin"
)

type EncodedKeys struct {
	ClientPriv string
	ClientPub  string
	ServerPub  string
	PreShared  string
}

type DecodedKeys struct {
	ClientPriv []byte
	ClientPub  []byte
	ServerPub  []byte
	PreShared  []byte
}

type Connection struct {
	conn     net.Conn
	Duration time.Duration
}

type Handshake struct {
	hs *noise.HandshakeState
	cs *noise.CipherSuite
}

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

	ClientAddress net.IP
	ServerAddress net.IP

	EncodedKeys *EncodedKeys
	DecodedKeys *DecodedKeys

	Handshake *Handshake

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
	CheckStageResults       []CheckStageResult
	FailedCheckStageResults []CheckStageResult

	NagiosPluginResult *NagiosPluginResult
	DebugMode          bool

	Connected bool

	Errors []error
}

type WireguardClientAndNagiosPluginResult struct {
	wgc    *WireguardClient
	result *NagiosPluginResult
}

type CheckStageResult struct {
	Name     string
	Started  time.Time
	Duration time.Duration

	Result interface{}
	Error  error

	Success  bool
	Function string
}

type NagiosPluginResult struct {
	Status  nagiosplugin.Status
	Message string
}
