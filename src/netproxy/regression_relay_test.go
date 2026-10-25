package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/loopback"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

func relayTCPStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s
}

func relayTCPPair(t *testing.T, s *stack.Stack) (*gonet.TCPConn, *gonet.TCPConn) {
	t.Helper()
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1})}
	listener, err := gonet.ListenTCP(s, addr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := gonet.DialContextTCP(ctx, s, addr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	peer := accepted.(*gonet.TCPConn)
	t.Cleanup(func() { client.Close(); peer.Close() })
	client.SetDeadline(time.Now().Add(2 * time.Second))
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	return client, peer
}

func runTCPRelay(t *testing.T, a, b net.Conn) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { relay(ctx, a, b, false); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("relay did not stop after cancellation")
		}
	})
	return done
}

func requireRelayStopped(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("closed TCP flow remained held")
	}
}

func TestRelayReleasesTwoHundredSequentialHTTPFlows(t *testing.T) {
	s := relayTCPStack(t)
	const response = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
	for i := 0; i < 210; i++ {
		client, guest := relayTCPPair(t, s)
		proxy, origin := relayTCPPair(t, s)
		done := runTCPRelay(t, guest, proxy)
		if _, err := client.Write([]byte("GET /")); err != nil {
			t.Fatalf("flow %d request: %v", i, err)
		}
		var request [5]byte
		if _, err := io.ReadFull(origin, request[:]); err != nil || string(request[:]) != "GET /" {
			t.Fatalf("flow %d request was not relayed: %q, %v", i, request, err)
		}
		if _, err := origin.Write([]byte(response)); err != nil {
			t.Fatalf("flow %d response: %v", i, err)
		}
		origin.Close()
		got, err := io.ReadAll(client)
		if err != nil || string(got) != response {
			t.Fatalf("flow %d response was truncated: %q, %v", i, got, err)
		}
		client.Close()
		requireRelayStopped(t, done)
	}
}

func TestRelayPreservesResponseAfterClientHalfClose(t *testing.T) {
	s := relayTCPStack(t)
	client, guest := relayTCPPair(t, s)
	proxy, origin := relayTCPPair(t, s)
	done := runTCPRelay(t, guest, proxy)
	client.Write([]byte("request before FIN"))
	client.CloseWrite()
	request, err := io.ReadAll(origin)
	if err != nil || string(request) != "request before FIN" {
		t.Fatalf("request half-close was not relayed: %q, %v", request, err)
	}
	origin.Write([]byte("response after FIN"))
	origin.CloseWrite()
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response after FIN" {
		t.Fatalf("half-close lost the response: %q, %v", response, err)
	}
	requireRelayStopped(t, done)
}

type failedReadTCPConn struct{ *gonet.TCPConn }

func (c *failedReadTCPConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

type failedWriteTCPConn struct{ *gonet.TCPConn }

func (c *failedWriteTCPConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

type failedCloseWriteTCPConn struct{ *gonet.TCPConn }

func (c *failedCloseWriteTCPConn) CloseWrite() error { return net.ErrClosed }

func TestRelayReleasesFlowAfterProxyReadFailure(t *testing.T) {
	s := relayTCPStack(t)
	_, guest := relayTCPPair(t, s)
	proxy, _ := relayTCPPair(t, s)
	done := runTCPRelay(t, guest, &failedReadTCPConn{proxy})
	requireRelayStopped(t, done)
}

func TestRelayReleasesFlowAfterProxyWriteFailure(t *testing.T) {
	s := relayTCPStack(t)
	client, guest := relayTCPPair(t, s)
	proxy, _ := relayTCPPair(t, s)
	done := runTCPRelay(t, guest, &failedWriteTCPConn{proxy})
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	requireRelayStopped(t, done)
}

func TestRelayReleasesFlowAfterHalfCloseFailure(t *testing.T) {
	s := relayTCPStack(t)
	client, guest := relayTCPPair(t, s)
	proxy, _ := relayTCPPair(t, s)
	done := runTCPRelay(t, guest, &failedCloseWriteTCPConn{proxy})
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requireRelayStopped(t, done)
}
