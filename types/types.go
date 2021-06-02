package types

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
	Hs *noise.HandshakeState
	Cs *noise.CipherSuite
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
