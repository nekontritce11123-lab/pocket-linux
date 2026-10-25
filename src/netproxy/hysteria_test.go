package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type fixtureServerTLS struct{ *standardTLSConfig }

func (c *fixtureServerTLS) Start() error { return nil }
func (c *fixtureServerTLS) Close() error { return nil }
func (c *fixtureServerTLS) Server(conn net.Conn) (aTLS.Conn, error) {
	return tls.Server(conn, c.config), nil
}
func (c *fixtureServerTLS) Clone() aTLS.Config {
	return &fixtureServerTLS{&standardTLSConfig{config: c.config.Clone(), timeout: c.timeout}}
}

type hysteriaFixture struct {
	certificate tls.Certificate
	roots       *x509.CertPool
	port        uint16
	obfs        string
	stop        func()
}

func fixtureCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PocketNet test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"proxy.test", "origin.test", "cloudflare-dns.com"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}, roots
}

func newHysteriaFixture(t *testing.T, obfs string) *hysteriaFixture {
	t.Helper()
	certificate, roots := fixtureCertificate(t)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &hysteriaFixture{certificate: certificate, roots: roots, port: uint16(packet.LocalAddr().(*net.UDPAddr).Port), obfs: obfs}
	service, err := hysteria2.NewService[string](hysteria2.ServiceOptions{
		Context: ctx, Logger: logger.NOP(), Handler: f, UDPTimeout: time.Second,
		SalamanderPassword: obfs, TLSConfig: &fixtureServerTLS{&standardTLSConfig{config: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}}},
	})
	if err != nil {
		cancel()
		packet.Close()
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"test"}, []string{"fixture-auth"})
	if err := service.Start(packet); err != nil {
		cancel()
		packet.Close()
		t.Fatal(err)
	}
	var once sync.Once
	f.stop = func() { once.Do(func() { cancel(); service.Close(); packet.Close() }) }
	t.Cleanup(f.stop)
	return f
}

func (f *hysteriaFixture) proxy(t *testing.T, edit func(*proxyConfig, *tls.Config)) *hysteriaProxy {
	t.Helper()
	c := proxyConfig{Type: "hysteria2", Server: "127.0.0.1", ServerPort: f.port, Password: "fixture-auth", TLSServerName: "proxy.test", ObfsPassword: f.obfs}
	tlsConfig := &tls.Config{ServerName: c.TLSServerName, RootCAs: f.roots, MinVersion: tls.VersionTLS13}
	if edit != nil {
		edit(&c, tlsConfig)
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy, err := newHysteriaProxy(ctx, c, &standardTLSConfig{config: tlsConfig, timeout: time.Second})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); proxy.Close() })
	return proxy
}

func (f *hysteriaFixture) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	switch destination.Port {
	case 53:
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if len(query) < 12 || len(query) > 4096 {
			return
		}
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		query[2] |= 0x80
		conn.Write(append(size[:], query...))
	case 443:
		tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.certificate}, MinVersion: tls.VersionTLS12}).HandshakeContext(ctx)
	case 18082:
		request, err := io.ReadAll(conn)
		if err == nil || errors.Is(err, io.EOF) {
			conn.Write(append([]byte("after FIN: "), request...))
		}
	case 18083:
		conn.Write([]byte("server banner"))
	default:
		io.Copy(conn, conn)
	}
}

func (f *hysteriaFixture) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	for {
		packet := buf.NewPacket()
		address, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return
		}
		if err := conn.WritePacket(packet, address); err != nil {
			return
		}
	}
}

func TestHysteriaTCPUDPDNSAndTLSProbe(t *testing.T) {
	for _, obfs := range []string{"", "fixture-salamander"} {
		t.Run("obfs="+obfs, func(t *testing.T) {
			f := newHysteriaFixture(t, obfs)
			proxy := f.proxy(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, network := range []string{"tcp", "udp"} {
				conn, err := proxy.DialContext(ctx, network, M.ParseSocksaddr("198.18.0.10:18080"))
				if err != nil {
					t.Fatal(network, err)
				}
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := conn.Write([]byte("echo")); err != nil {
					t.Fatal(err)
				}
				var got [4]byte
				if _, err := io.ReadFull(conn, got[:]); err != nil || string(got[:]) != "echo" {
					t.Fatalf("%s echo: %q, %v", network, got, err)
				}
				conn.Close()
			}
			query := []byte{0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			answer := dnsRequest(ctx, proxy, "198.18.0.53:53", query)
			if len(answer) != len(query) || answer[0] != 0x12 || answer[1] != 0x34 || answer[2]&0x80 == 0 {
				t.Fatal("DNS was not carried inside the authenticated Hysteria2 stream")
			}
			if err := probeOutbound(ctx, proxy, "198.18.0.10:443", &tls.Config{ServerName: "origin.test", RootCAs: f.roots, MinVersion: tls.VersionTLS12}); err != nil {
				t.Fatal("TLS probe:", err)
			}
		})
	}
}

func TestHysteriaHalfCloseKeepsResponseReadable(t *testing.T) {
	f := newHysteriaFixture(t, "")
	proxy := f.proxy(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.10:18082"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("request"))
	halfClose, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("Hysteria2 must expose write-only FIN")
	}
	if err := halfClose.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "after FIN: request" {
		t.Fatalf("response after FIN: %q, %v", response, err)
	}
}

func TestHysteriaSendsDestinationBeforeServerFirstRead(t *testing.T) {
	f := newHysteriaFixture(t, "")
	proxy := f.proxy(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.10:18083"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "server banner" {
		t.Fatalf("server-first protocol stalled: %q, %v", response, err)
	}
}

func TestHysteriaRejectsAuthenticationAndCertificateFailures(t *testing.T) {
	f := newHysteriaFixture(t, "")
	for name, edit := range map[string]func(*proxyConfig, *tls.Config){
		"password": func(c *proxyConfig, config *tls.Config) { c.Password = "wrong-auth" },
		"hostname": func(c *proxyConfig, config *tls.Config) { config.ServerName = "wrong.test" },
		"CA":       func(c *proxyConfig, config *tls.Config) { config.RootCAs = x509.NewCertPool() },
	} {
		t.Run(name, func(t *testing.T) {
			proxy := f.proxy(t, edit)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.10:18080")); err == nil || conn != nil {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("unverified or unauthenticated tunnel accepted")
			}
		})
	}
}

func TestHysteriaStopsAfterServerDrop(t *testing.T) {
	f := newHysteriaFixture(t, "")
	proxy := f.proxy(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr("198.18.0.10:18080"))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("ok"))
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	f.stop()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(reply[:]); err == nil {
		t.Fatal("closed upstream remained readable")
	}
	conn.Close()
	short, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	// QUIC can create a buffered stream before detecting a blackhole; require a real verified response.
	if err := probeOutbound(short, proxy, "198.18.0.10:443", &tls.Config{ServerName: "origin.test", RootCAs: f.roots, MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS succeeded after the selected upstream stopped")
	}
}

func TestHysteriaHostDialerCannotEscapePinnedUDPEndpoint(t *testing.T) {
	dialer := pinnedQUICDialer{netip.MustParseAddrPort("127.0.0.1:443")}
	for _, test := range []struct{ network, destination string }{
		{"tcp", "127.0.0.1:443"}, {"udp", "127.0.0.1:444"}, {"udp", "1.1.1.1:443"}, {"udp", "localhost:443"}, {"udp", "[::1]:443"}, {"udp", "0.0.0.0:443"},
	} {
		if conn, err := dialer.DialContext(context.Background(), test.network, M.ParseSocksaddr(test.destination)); err == nil || conn != nil {
			t.Fatal("host dial escaped selected Hysteria2 endpoint")
		}
	}
	if conn, err := dialer.ListenPacket(context.Background(), M.ParseSocksaddr("0.0.0.0:0")); err == nil || conn != nil {
		t.Fatal("unconnected host packet socket accepted")
	}
}

func TestProbeFailureNeverPrintsProxySecrets(t *testing.T) {
	c, err := parseConfig([]byte(validHysteriaConfig))
	if err != nil {
		t.Fatal(err)
	}
	c.Proxy.Server = "127.0.0.1"
	c.Proxy.ServerPort = 1
	c.Proxy.Password = "SECRET-AUTH-DO-NOT-PRINT"
	c.Proxy.ObfsPassword = "SECRET-OBFS-DO-NOT-PRINT"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := runProbe(ctx, c, &output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("SECRET")) || !bytes.Contains(output.Bytes(), []byte(`"ok":false`)) || !bytes.Contains(output.Bytes(), []byte(`"protocol":"hysteria2"`)) {
		t.Fatal("probe result leaked configuration or lost its result contract")
	}
}
