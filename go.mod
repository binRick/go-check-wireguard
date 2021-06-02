module wg

go 1.16

replace github.com/binrick/go-check-wireguard/types => ./types/.

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/binrick/go-check-wireguard/types v0.0.0-00010101000000-000000000000
	github.com/flynn/noise v1.0.0
	github.com/google/gopacket v1.1.19
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/olorin/nagiosplugin v1.2.0
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/sys v0.0.0-20210601080250-7ecdf8ef093b
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)
