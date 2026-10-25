package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func connectFixture(t *testing.T, secure *tls.Config, serve func(net.Conn)) config {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if secure != nil {
			conn = tls.Server(conn, secure)
		}
		serve(conn)
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("CONNECT fixture did not stop")
		}
	})
	return config{DNSUpstream: "198.18.0.53:53", Proxy: proxyConfig{Type: "http", Server: "127.0.0.1", ServerPort: uint16(listener.Addr().(*net.TCPAddr).Port)}}
}

func TestCONNECTAuthBufferedBytesAndHalfClose(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			certificate, roots := fixtureCertificate(t)
			var serverTLS *tls.Config
			if secure {
				serverTLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
			}
			requests := make(chan *http.Request, 1)
			c := connectFixture(t, serverTLS, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				requests <- request
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nbanner"))
				body, err := io.ReadAll(reader)
				if err != nil {
					return
				}
				conn.Write(append([]byte("after FIN: "), body...))
			})
			c.Proxy.Username, c.Proxy.Password = "alice", "secret:with:colons"
			if secure {
				c.Proxy.Type, c.Proxy.TLSServerName = "https", "proxy.test"
			}
			proxy, err := newProxy(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if secure {
				proxy.(*connectProxy).tlsConfig.RootCAs = roots
			}
			conn, err := proxyConnect(context.Background(), proxy, "tcp", "198.18.0.10:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			request := <-requests
			if request.Method != "CONNECT" || request.Host != "198.18.0.10:443" || request.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret:with:colons")) {
				t.Fatalf("wrong CONNECT request: %+v", request)
			}
			banner := make([]byte, 6)
			if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "banner" {
				t.Fatalf("lost buffered bytes: %q %v", banner, err)
			}
			conn.Write([]byte("request"))
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			answer, err := io.ReadAll(conn)
			if err != nil || string(answer) != "after FIN: request" {
				t.Fatalf("half-close lost reply: %q %v", answer, err)
			}
		})
	}
}

func TestCONNECTFailsClosed(t *testing.T) {
	p := &connectProxy{server: netip.MustParseAddrPort("127.0.0.1:1")}
	for _, test := range []struct{ network, destination string }{{"udp", "1.1.1.1:443"}, {"tcp", "127.0.0.1:80"}, {"tcp", "example.com:443"}, {"tcp", "[::1]:443"}} {
		if conn, err := p.DialContext(context.Background(), test.network, M.ParseSocksaddr(test.destination)); conn != nil || err == nil {
			t.Fatalf("unsafe dial accepted: %+v", test)
		}
	}
	for _, response := range []string{"HTTP/1.1 407 Authentication Required\r\n\r\n", "HTTP/1.1 502 Bad Gateway\r\n\r\n", "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 65536) + "\r\n\r\n"} {
		c := connectFixture(t, nil, func(conn net.Conn) { http.ReadRequest(bufio.NewReader(conn)); io.WriteString(conn, response) })
		proxy, err := newProxy(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := proxyConnect(context.Background(), proxy, "tcp", "1.1.1.1:443"); conn != nil || err == nil {
			t.Fatal("refused or oversized CONNECT response accepted")
		}
	}
}

func TestHTTPSRejectsUntrustedCertificateAndWrongName(t *testing.T) {
	for _, wrongName := range []bool{false, true} {
		certificate, roots := fixtureCertificate(t)
		c := connectFixture(t, &tls.Config{Certificates: []tls.Certificate{certificate}}, func(conn net.Conn) {
			if err := conn.(*tls.Conn).Handshake(); err == nil {
				t.Error("invalid TLS peer was accepted")
			}
		})
		c.Proxy.Type, c.Proxy.TLSServerName = "https", "proxy.test"
		proxy, err := newProxy(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if wrongName {
			proxy.(*connectProxy).tlsConfig.RootCAs = roots
			proxy.(*connectProxy).tlsConfig.ServerName = "wrong.test"
		}
		if conn, err := proxyConnect(context.Background(), proxy, "tcp", "1.1.1.1:443"); conn != nil || err == nil {
			t.Fatal("invalid TLS peer accepted")
		}
	}
}

func TestCONNECTConfig(t *testing.T) {
	for _, protocol := range []string{"http", "https"} {
		text := strings.Replace(validConfig, "socks5", protocol, 1)
		if protocol == "https" {
			text = strings.Replace(text, `"server_port":1080`, `"server_port":1080,"tls_server_name":"proxy.test"`, 1)
		}
		if _, err := parseConfig([]byte(text)); err != nil {
			t.Fatal(err)
		}
		for _, invalid := range []string{
			strings.Replace(text, `"server_port":1080`, `"server_port":1080,"username":"a:b"`, 1),
			strings.Replace(text, `"server_port":1080`, `"server_port":1080,"obfs_password":"xxxx"`, 1),
			strings.Replace(text, `"proxy":{`, `"direct_fallback":true,"proxy":{`, 1),
			strings.Replace(text, `"server":"127.0.0.1"`, `"server":"proxy.test"`, 1),
		} {
			if _, err := parseConfig([]byte(invalid)); err == nil {
				t.Fatal("invalid CONNECT config accepted")
			}
		}
	}
	for _, text := range []string{
		strings.Replace(validConfig, "socks5", "https", 1),
		strings.Replace(strings.Replace(validConfig, "socks5", "http", 1), `"server_port":1080`, `"server_port":1080,"tls_server_name":"proxy.test"`, 1),
	} {
		if _, err := parseConfig([]byte(text)); err == nil {
			t.Fatal("invalid TLS options accepted")
		}
	}
}

func TestCONNECTBufferedReaderBeyondHeaderLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), 100000)
	c := connectFixture(t, nil, func(conn net.Conn) {
		http.ReadRequest(bufio.NewReader(conn))
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		conn.Write(payload)
	})
	proxy, err := newProxy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proxyConnect(context.Background(), proxy, "tcp", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	answer, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(answer, payload) {
		t.Fatalf("tunnel truncated at header limit: %d, %v", len(answer), err)
	}
}
