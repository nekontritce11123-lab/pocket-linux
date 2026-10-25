package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var dnsQuery = []byte{0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func dnsAnswer() []byte {
	answer := bytes.Clone(dnsQuery)
	answer[2] |= 0x80
	return answer
}

// No external socket is opened: this fake proxy terminates the tunneled TLS peer.
func dohFixture(t *testing.T, httpsProxy bool, edit func(*tls.Config), response func(net.Conn, *http.Request)) *connectProxy {
	t.Helper()
	certificate, roots := fixtureCertificate(t)
	var outerTLS *tls.Config
	if httpsProxy {
		outerTLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	}
	c := connectFixture(t, outerTLS, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		connect, err := http.ReadRequest(reader)
		if err != nil {
			t.Error(err)
			return
		}
		if connect.Method != "CONNECT" || connect.Host != "1.1.1.1:443" {
			t.Errorf("443-only proxy refused destination: %s %s", connect.Method, connect.Host)
			io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		secure := tls.Server(&connectConn{Conn: conn, reader: reader}, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := secure.Handshake(); err != nil {
			return // Negative tests deliberately reject this certificate or name.
		}
		defer secure.Close()
		if secure.ConnectionState().ServerName != "cloudflare-dns.com" && edit == nil {
			t.Error("DoH TLS did not send its certificate name")
		}
		request, err := http.ReadRequest(bufio.NewReader(secure))
		if err != nil {
			t.Error(err)
			return
		}
		defer request.Body.Close()
		body, err := io.ReadAll(io.LimitReader(request.Body, 4097))
		if err != nil || !bytes.Equal(body, dnsQuery) || request.Method != "POST" || request.Host != "cloudflare-dns.com" || request.URL.Path != "/dns-query" || request.Header.Get("Content-Type") != "application/dns-message" || request.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("invalid DoH request: %+v body=%x err=%v", request, body, err)
			return
		}
		response(secure, request)
	})
	if httpsProxy {
		c.Proxy.Type, c.Proxy.TLSServerName = "https", "proxy.test"
	}
	proxy, err := newProxy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.(*connectProxy)
	p.dnsTLSConfig.RootCAs = roots
	if httpsProxy {
		p.tlsConfig.RootCAs = roots
	}
	if edit != nil {
		edit(p.dnsTLSConfig)
	}
	return p
}

func writeDNSResponse(conn net.Conn, status int, contentType string, body []byte) {
	fmt.Fprintf(conn, "HTTP/1.1 %d Response\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, contentType, len(body))
	conn.Write(body)
}

func TestCONNECTDNSUsesDoHThrough443OnlyProxy(t *testing.T) {
	for _, httpsProxy := range []bool{false, true} {
		for _, tcpGuest := range []bool{false, true} {
			t.Run(fmt.Sprintf("httpsProxy=%t/tcpGuest=%t", httpsProxy, tcpGuest), func(t *testing.T) {
				p := dohFixture(t, httpsProxy, nil, func(conn net.Conn, _ *http.Request) {
					writeDNSResponse(conn, 200, "application/dns-message", dnsAnswer())
				})
				if !tcpGuest {
					answer := dnsRequest(context.Background(), p, "198.18.0.53:53", dnsQuery)
					if !bytes.Equal(answer, dnsAnswer()) {
						t.Fatalf("DoH answer missing: %x", answer)
					}
					return
				}
				guest, gateway := net.Pipe()
				defer guest.Close()
				guest.SetDeadline(time.Now().Add(3 * time.Second))
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan struct{})
				go func() { dnsTCPExchange(ctx, p, "198.18.0.53:53", gateway); close(done) }()
				var size [2]byte
				binary.BigEndian.PutUint16(size[:], uint16(len(dnsQuery)))
				guest.Write(append(size[:], dnsQuery...))
				if _, err := io.ReadFull(guest, size[:]); err != nil {
					t.Fatal(err)
				}
				answer := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(guest, answer); err != nil || !bytes.Equal(answer, dnsAnswer()) {
					t.Fatalf("TCP DNS response missing: %x %v", answer, err)
				}
				guest.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("TCP DNS handler leaked")
				}
			})
		}
	}
}

func TestCONNECTDoHRejectsInvalidTLS(t *testing.T) {
	for _, edit := range []func(*tls.Config){
		func(c *tls.Config) { c.ServerName = "wrong.test" },
		func(c *tls.Config) { c.RootCAs, _ = trustedRoots() },
	} {
		p := dohFixture(t, false, edit, func(net.Conn, *http.Request) { t.Error("invalid TLS reached DoH") })
		if answer := dnsRequest(context.Background(), p, "1.1.1.1:53", dnsQuery); answer != nil {
			t.Fatalf("invalid TLS accepted: %x", answer)
		}
	}
}

func TestCONNECTDoHRejectsBadResponsesAndProxyLoss(t *testing.T) {
	wrongID := dnsAnswer()
	wrongID[0]++
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        []byte
	}{
		{"redirect", 302, "application/dns-message", dnsAnswer()},
		{"failure", 502, "application/dns-message", dnsAnswer()},
		{"wrong-type", 200, "text/html", dnsAnswer()},
		{"wrong-id", 200, "application/dns-message", wrongID},
		{"query-not-response", 200, "application/dns-message", dnsQuery},
		{"short", 200, "application/dns-message", []byte{1, 2}},
		{"oversize", 200, "application/dns-message", bytes.Repeat([]byte{0}, 4097)},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := dohFixture(t, false, nil, func(conn net.Conn, _ *http.Request) { writeDNSResponse(conn, test.status, test.contentType, test.body) })
			if answer := dnsRequest(context.Background(), p, "1.1.1.1:53", dnsQuery); answer != nil {
				t.Fatalf("bad DoH accepted: %x", answer)
			}
		})
	}
	for _, response := range []string{"", "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 20\r\n\r\nx", "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 65536) + "\r\n\r\n"} {
		p := dohFixture(t, false, nil, func(conn net.Conn, _ *http.Request) { io.WriteString(conn, response) })
		if answer := dnsRequest(context.Background(), p, "1.1.1.1:53", dnsQuery); answer != nil {
			t.Fatalf("lost/truncated DoH accepted: %x", answer)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	p := &connectProxy{server: netip.MustParseAddrPort(address)}
	if answer := p.DNSRequest(context.Background(), dnsQuery); answer != nil {
		t.Fatalf("dead proxy returned DNS: %x", answer)
	}
	for _, query := range [][]byte{nil, make([]byte, 4097)} {
		if answer := p.DNSRequest(context.Background(), query); answer != nil {
			t.Fatal("invalid query accepted")
		}
	}
}
