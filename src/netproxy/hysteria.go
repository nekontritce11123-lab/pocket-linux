package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// QUIC may open only the one selected UDP endpoint, including after reconnects.
type pinnedQUICDialer struct{ server netip.AddrPort }

func (d pinnedQUICDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "udp" || dst.IsDomain() || !dst.Addr.Is4() || netip.AddrPortFrom(dst.Addr, dst.Port) != d.server {
		return nil, errors.New("QUIC connection outside selected proxy refused")
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp4", d.server.String())
}

func (d pinnedQUICDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unconnected QUIC sockets forbidden")
}

type standardTLSConfig struct {
	config  *tls.Config
	timeout time.Duration
}

func (c *standardTLSConfig) ServerName() string                        { return c.config.ServerName }
func (c *standardTLSConfig) SetServerName(name string)                 { c.config.ServerName = name }
func (c *standardTLSConfig) NextProtos() []string                      { return c.config.NextProtos }
func (c *standardTLSConfig) SetNextProtos(protocols []string)          { c.config.NextProtos = protocols }
func (c *standardTLSConfig) HandshakeTimeout() time.Duration           { return c.timeout }
func (c *standardTLSConfig) SetHandshakeTimeout(timeout time.Duration) { c.timeout = timeout }
func (c *standardTLSConfig) STDConfig() (*tls.Config, error)           { return c.config, nil }
func (c *standardTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}
func (c *standardTLSConfig) Clone() aTLS.Config {
	return &standardTLSConfig{config: c.config.Clone(), timeout: c.timeout}
}

type hysteriaProxy struct{ client *hysteria2.Client }

type hysteriaConn struct{ net.Conn }

func (c *hysteriaConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if errors.Is(err, io.EOF) {
		err = io.EOF
	}
	return n, err
}

func (c *hysteriaConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.New("Hysteria2 transport lacks half-close support")
}

func newHysteriaProxy(ctx context.Context, c proxyConfig, tlsConfig aTLS.Config) (*hysteriaProxy, error) {
	server := netip.AddrPortFrom(netip.MustParseAddr(c.Server), c.ServerPort)
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context: ctx, Dialer: pinnedQUICDialer{server}, Logger: logger.NOP(),
		ServerAddress: M.ParseSocksaddr(server.String()), Password: c.Password,
		SalamanderPassword: c.ObfsPassword, TLSConfig: tlsConfig,
		QUICOptions: qtls.QUICOptions{StreamReceiveWindow: 1 << 20, ConnectionReceiveWindow: 8 << 20, MaxConcurrentStreams: 128},
	})
	if err != nil {
		return nil, err
	}
	return &hysteriaProxy{client: client}, nil
}

func (p *hysteriaProxy) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !allowedDestination(destination.String()) {
		return nil, errors.New("non-public guest destination refused")
	}
	switch network {
	case "tcp":
		conn, err := p.client.DialConn(ctx, destination)
		if err != nil {
			return nil, err
		}
		// DialConn is lazy: send its destination before waiting for server-first protocols.
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		_, err = conn.Write(nil)
		if !stop() {
			conn.Close()
			return nil, ctx.Err()
		}
		if err != nil {
			conn.Close()
			return nil, err
		}
		return &hysteriaConn{Conn: conn}, nil
	case "udp":
		packet, err := p.client.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packet, destination.UDPAddr()), nil
	default:
		return nil, errors.New("unsupported guest network")
	}
}

func (p *hysteriaProxy) Close() error { return p.client.CloseWithError(net.ErrClosed) }
