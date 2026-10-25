package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// Only this dialer can open host connections; guest destinations never reach it.
type pinnedDialer struct{ server netip.AddrPort }

func (d pinnedDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if dst.IsDomain() || !dst.Addr.Is4() {
		return nil, errors.New("proxy relay must be a literal IPv4 address")
	}
	if network == "udp" && dst.Addr.IsUnspecified() {
		dst.Addr = d.server.Addr()
	}
	if dst.Addr != d.server.Addr() || dst.Port == 0 || (network == "tcp" && dst.Port != d.server.Port()) || (network != "tcp" && network != "udp") {
		return nil, errors.New("host connection outside selected proxy refused")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network+"4", dst.String())
}

func (d pinnedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unconnected host UDP sockets forbidden")
}

type outboundProxy interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	Close() error
}

type socksProxy struct{ *socks.Client }

func (p *socksProxy) Close() error { return nil }

func newProxy(ctx context.Context, c config) (outboundProxy, error) {
	server := netip.AddrPortFrom(netip.MustParseAddr(c.Proxy.Server), c.Proxy.ServerPort)
	switch c.Proxy.Type {
	case "socks5":
		return &socksProxy{socks.NewClient(pinnedDialer{server}, M.ParseSocksaddr(server.String()), socks.Version5, c.Proxy.Username, c.Proxy.Password)}, nil
	case "http", "https":
		p := &connectProxy{server: server, username: c.Proxy.Username, password: c.Proxy.Password}
		roots, err := trustedRoots()
		if err != nil {
			return nil, err
		}
		p.dnsTLSConfig = &tls.Config{ServerName: "cloudflare-dns.com", RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		if c.Proxy.Type == "https" {
			p.tlsConfig = &tls.Config{ServerName: c.Proxy.TLSServerName, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		}
		return p, nil
	case "hysteria2":
		roots, err := trustedRoots()
		if err != nil {
			return nil, err
		}
		return newHysteriaProxy(ctx, c.Proxy, &standardTLSConfig{config: &tls.Config{ServerName: c.Proxy.TLSServerName, RootCAs: roots, MinVersion: tls.VersionTLS13}, timeout: 5 * time.Second})
	default:
		return nil, errors.New("unsupported outbound proxy")
	}
}

// The library's net.Conn UDP facade changes its destination when reading a reply.
// Keep each guest flow fixed and use the independent PacketConn API in both directions.
type fixedPacketConn struct {
	net.Conn
	packet      net.PacketConn
	destination net.Addr
}

func (c *fixedPacketConn) Read(b []byte) (int, error) {
	for {
		n, source, err := c.packet.ReadFrom(b)
		if err != nil {
			return n, err
		}
		if source != nil && source.String() == c.destination.String() {
			return n, nil
		}
	}
}

func (c *fixedPacketConn) Write(b []byte) (int, error) {
	n, err := c.packet.WriteTo(b, c.destination)
	if n > len(b) {
		n = len(b)
	} // SOCKS WriteTo counts its envelope as well as the payload.
	return n, err
}

func (c *fixedPacketConn) RemoteAddr() net.Addr { return c.destination }
