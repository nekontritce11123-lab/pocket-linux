package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type connectProxy struct {
	server             netip.AddrPort
	username, password string
	tlsConfig          *tls.Config
	dnsTLSConfig       *tls.Config
}

func (p *connectProxy) Close() error { return nil }

func (p *connectProxy) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || !allowedDestination(destination.String()) {
		return nil, errors.New("CONNECT permits only public IPv4 TCP destinations")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (pinnedDialer{p.server}).DialContext(ctx, "tcp", M.ParseSocksaddr(p.server.String()))
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	success := false
	defer func() {
		if !success {
			stop()
			conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	transport := conn
	if p.tlsConfig != nil {
		secure := tls.Client(conn, p.tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		transport = secure
	}
	address := destination.String()
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if p.username != "" || p.password != "" {
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.username+":"+p.password)))
	}
	if err = request.Write(transport); err != nil {
		return nil, err
	}
	// Bound response headers while retaining any tunnel bytes read ahead with them.
	reader := bufio.NewReader(io.LimitReader(transport, 65536))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("CONNECT proxy refused the tunnel")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	transport.SetDeadline(time.Time{})
	if !stop() {
		return nil, ctx.Err()
	}
	success = true
	return &connectConn{Conn: transport, reader: io.MultiReader(reader, transport)}, nil
}

type connectConn struct {
	net.Conn
	reader io.Reader
}

func (c *connectConn) Read(data []byte) (int, error) { return c.reader.Read(data) }
func (c *connectConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.New("CONNECT transport lacks half-close support")
}

// Match the Windows edition's secure DNS through the same pinned proxy, using
// port 443 so CONNECT proxies need not allow raw DNS connections on port 53.
func (p *connectProxy) DNSRequest(ctx context.Context, query []byte) []byte {
	if len(query) < 12 || len(query) > 4096 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := p.DialContext(ctx, "tcp", M.ParseSocksaddr("1.1.1.1:443"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	secure := tls.Client(conn, p.dnsTLSConfig)
	if err = secure.HandshakeContext(ctx); err != nil {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Close = true
	if err = request.Write(secure); err != nil {
		return nil
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, 65536)), request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != http.StatusOK || contentType != "application/dns-message" {
		return nil
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(answer) < 12 || len(answer) > 4096 || !bytes.Equal(answer[:2], query[:2]) || answer[2]&0x80 == 0 {
		return nil
	}
	return answer
}
