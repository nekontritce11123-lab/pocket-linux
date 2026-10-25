package main

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"net/netip"
	"testing"
)

func TestHostDialerRejectsEveryDestinationExceptPinnedProxy(t *testing.T) {
	d := pinnedDialer{netip.MustParseAddrPort("127.0.0.1:1080")}
	for _, test := range []struct{ network, destination string }{
		{"tcp", "1.1.1.1:443"}, {"tcp", "127.0.0.1:1081"}, {"tcp", "localhost:1080"},
		{"udp", "192.168.0.1:53"}, {"tcp", "[::1]:1080"}, {"icmp", "127.0.0.1:1080"},
	} {
		conn, err := d.DialContext(context.Background(), test.network, M.ParseSocksaddr(test.destination))
		if err == nil || conn != nil {
			t.Errorf("host dial escaped: %v", test)
		}
	}
	if conn, err := d.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53")); err == nil || conn != nil {
		t.Fatal("unconnected UDP socket permitted")
	}
}

type fakePacket struct {
	net.Conn
	reads   int
	written net.Addr
}

func (f *fakePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	f.reads++
	source := "198.18.0.99:18081"
	if f.reads > 1 {
		source = "198.18.0.10:18081"
	}
	copy(b, "ok")
	return 2, M.ParseSocksaddr(source).UDPAddr(), nil
}
func (f *fakePacket) WriteTo(b []byte, a net.Addr) (int, error) {
	f.written = a
	return len(b) + 10, nil
}

func TestUDPFlowCannotBeRetargetedByAProxyReply(t *testing.T) {
	p := &fakePacket{}
	dst := M.ParseSocksaddr("198.18.0.10:18081").UDPAddr()
	c := &fixedPacketConn{Conn: p, packet: p, destination: dst}
	if n, err := c.Read(make([]byte, 20)); n != 2 || err != nil || p.reads != 2 {
		t.Fatal("unexpected-source datagram was accepted")
	}
	if n, err := c.Write([]byte("x")); n != 1 || err != nil || p.written.String() != dst.String() {
		t.Fatal("UDP destination or byte count changed")
	}
}
