module pocketlinux/netproxy

go 1.25.5

require (
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1
	github.com/sagernet/sing v0.9.7-0.20260929150544-0ad23b637bd4
	github.com/sagernet/sing-quic v0.7.2-0.20261002084117-75c3ac4fa12b
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.9 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/sagernet/sing-quic => ./third_party/sing-quic
