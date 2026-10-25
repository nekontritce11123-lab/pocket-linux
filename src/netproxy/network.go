package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/link/ethernet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/arp"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	M "github.com/sagernet/sing/common/metadata"
)

const gatewayIP = "192.168.127.1"

func destination(id stack.TransportEndpointID, c config) (string, bool) {
	addr := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
	if id.LocalAddress.String() == gatewayIP && id.LocalPort == 53 {
		return c.DNSUpstream, true
	}
	return addr, allowedDestination(addr)
}

func proxyConnect(ctx context.Context, proxy outboundProxy, network, destination string) (net.Conn, error) {
	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return proxy.DialContext(timeout, network, M.ParseSocksaddr(destination))
}

type activityConn struct {
	net.Conn
	touch func()
}

func (c *activityConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 || err == nil {
		c.touch()
	}
	return n, err
}

func (c *activityConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 || err == nil {
		c.touch()
	}
	return n, err
}

func relay(ctx context.Context, a, b net.Conn, datagram bool) {
	defer a.Close()
	defer b.Close()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	idle := 10 * time.Minute
	if datagram {
		idle = time.Minute
	}
	var activity sync.Mutex
	touch := func() {
		activity.Lock()
		defer activity.Unlock()
		deadline := time.Now().Add(idle)
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
	}
	touch()
	done := make(chan struct{}, 1)
	copyOne := func(dst, src net.Conn) {
		activeSrc := &activityConn{Conn: src, touch: touch}
		activeDst := &activityConn{Conn: dst, touch: touch}
		if datagram {
			data := make([]byte, 65535)
			for {
				n, err := activeSrc.Read(data)
				if err != nil {
					break
				}
				if _, err = activeDst.Write(data[:n]); err != nil {
					break
				}
			}
		} else {
			if _, err := io.Copy(activeDst, activeSrc); err != nil {
				a.Close()
				b.Close()
				return
			}
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				if err := cw.CloseWrite(); err != nil {
					a.Close()
					b.Close()
				}
			} else {
				dst.Close()
			}
		}
	}
	go func() { copyOne(a, b); done <- struct{}{} }()
	copyOne(b, a)
	if datagram {
		a.Close()
		b.Close()
	}
	<-done
}

func dnsExchange(ctx context.Context, proxy outboundProxy, upstream string, guest net.Conn) {
	defer guest.Close()
	stop := context.AfterFunc(ctx, func() { guest.Close() })
	defer stop()
	query := make([]byte, 4096)
	for {
		guest.SetDeadline(time.Now().Add(20 * time.Second))
		n, err := guest.Read(query)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		answer := dnsRequest(ctx, proxy, upstream, query[:n])
		if len(answer) > 0 {
			if _, err = guest.Write(answer); err != nil {
				return
			}
		}
	}
}

type dnsProxy interface {
	DNSRequest(context.Context, []byte) []byte
}

func dnsTCPExchange(ctx context.Context, proxy outboundProxy, upstream string, guest net.Conn) {
	defer guest.Close()
	stop := context.AfterFunc(ctx, func() { guest.Close() })
	defer stop()
	for {
		guest.SetDeadline(time.Now().Add(20 * time.Second))
		var size [2]byte
		if _, err := io.ReadFull(guest, size[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length < 12 || length > 4096 {
			return
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(guest, query); err != nil {
			return
		}
		answer := dnsRequest(ctx, proxy, upstream, query)
		if len(answer) == 0 {
			return
		}
		binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
		if _, err := guest.Write(append(size[:], answer...)); err != nil {
			return
		}
	}
}

func dnsRequest(ctx context.Context, proxy outboundProxy, upstream string, query []byte) []byte {
	if resolver, ok := proxy.(dnsProxy); ok {
		return resolver.DNSRequest(ctx, query)
	}
	remote, err := proxyConnect(ctx, proxy, "tcp", upstream)
	if err != nil {
		return nil
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Second))
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	packet := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(query)))
	copy(packet[2:], query)
	if _, err = remote.Write(packet); err != nil {
		return nil
	}
	var size [2]byte
	if _, err = io.ReadFull(remote, size[:]); err != nil {
		return nil
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < 12 || length > 4096 {
		return nil
	}
	answer := make([]byte, length)
	if _, err = io.ReadFull(remote, answer); err != nil || answer[0] != query[0] || answer[1] != query[1] {
		return nil
	}
	return answer
}

func serveGuest(parent context.Context, wire net.Conn, c config) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer wire.Close()
	link := channel.New(256, 1514, tcpip.LinkAddress("\x52\x54\x00\x50\x4c\x02"))
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	defer s.Close()
	defer link.Close()
	if err := s.CreateNIC(1, ethernet.New(link)); err != nil {
		return errors.New(err.String())
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{192, 168, 127, 1}).WithPrefix()}, stack.AddressProperties{}); err != nil {
		return errors.New(err.String())
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	proxy, err := newProxy(ctx, c)
	if err != nil {
		return err
	}
	defer proxy.Close()
	flows := make(chan struct{}, 128)
	acquire := func() bool {
		select {
		case flows <- struct{}{}:
			return true
		default:
			return false
		}
	}
	release := func() { <-flows }
	tcpForwarder := tcp.NewForwarder(s, 0, 128, func(r *tcp.ForwarderRequest) {
		dst, ok := destination(r.ID(), c)
		if !ok || !acquire() {
			r.Complete(true)
			return
		}
		go func() {
			defer release()
			if _, doh := proxy.(dnsProxy); doh && r.ID().LocalPort == 53 {
				var wq waiter.Queue
				ep, epErr := r.CreateEndpoint(&wq)
				r.Complete(epErr != nil)
				if epErr == nil {
					dnsTCPExchange(ctx, proxy, c.DNSUpstream, gonet.NewTCPConn(&wq, ep))
				}
				return
			}
			remote, err := proxyConnect(ctx, proxy, "tcp", dst)
			if err != nil {
				r.Complete(true)
				return
			}
			var wq waiter.Queue
			ep, epErr := r.CreateEndpoint(&wq)
			r.Complete(epErr != nil)
			if epErr != nil {
				remote.Close()
				return
			}
			relay(ctx, gonet.NewTCPConn(&wq, ep), remote, false)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		dst, ok := destination(id, c)
		if !ok || !acquire() {
			return true
		}
		var wq waiter.Queue
		// This synchronous constructor borrows the packet; NewForwarder would clone it without releasing it in this fork.
		ep, epErr := udp.NewForwarderRequest(s, id, pkt).CreateEndpoint(&wq)
		if epErr != nil {
			release()
			return true
		}
		guest := gonet.NewUDPConn(&wq, ep)
		go func() {
			defer release()
			if id.LocalPort == 53 {
				dnsExchange(ctx, proxy, c.DNSUpstream, guest)
				return
			}
			remote, err := proxyConnect(ctx, proxy, "udp", dst)
			if err != nil {
				guest.Close()
				return
			}
			fixed := &fixedPacketConn{Conn: remote, packet: remote.(net.PacketConn), destination: M.ParseSocksaddr(dst).UDPAddr()}
			relay(ctx, guest, fixed, true)
		}()
		return true
	})
	go func() {
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			wire.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeFrame(wire, view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil {
				wire.Close()
				cancel()
				return
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() { wire.Close() })
	defer stop()
	for {
		frame, err := readFrame(wire)
		if err != nil {
			return err
		}
		// IPv6 and every non-IPv4/non-ARP protocol are closed at the guest link.
		typ := binary.BigEndian.Uint16(frame[12:14])
		if typ != uint16(ipv4.ProtocolNumber) && typ != uint16(arp.ProtocolNumber) {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
		link.InjectInbound(0, pkt)
		pkt.DecRef()
	}
}
