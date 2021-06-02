module test1

go 1.16

replace github.com/binrick/go-check-wireguard => ../../.

replace github.com/binrick/go-check-wireguard/types => ../../types/.

require (
	github.com/binrick/go-check-wireguard/types v0.0.0-00010101000000-000000000000
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/mattn/go-colorable v0.1.8 // indirect
)
