package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Keep the production relay path, shortening only its socket deadlines for the test.
type shortDeadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *shortDeadlineConn) SetDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(c.idle)
	}
	return c.Conn.SetDeadline(deadline)
}

func relayPair(t *testing.T, datagram bool, idle time.Duration) (net.Conn, net.Conn, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	a, client := net.Pipe()
	b, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		relay(ctx, &shortDeadlineConn{Conn: a, idle: idle}, &shortDeadlineConn{Conn: b, idle: idle}, datagram)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("relay did not release its connections")
		}
	})
	return client, server, cancel, done
}

func TestRelayKeepsActiveSession(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		t.Run(fmt.Sprintf("datagram=%t", datagram), func(t *testing.T) {
			const idle = 300 * time.Millisecond
			client, server, _, done := relayPair(t, datagram, idle)
			started := time.Now()
			for i := 0; i < 8; i++ {
				client.SetWriteDeadline(time.Now().Add(time.Second))
				server.SetReadDeadline(time.Now().Add(time.Second))
				writeDone := make(chan error, 1)
				go func() { _, err := client.Write([]byte("active")); writeDone <- err }()
				var received [6]byte
				if _, err := io.ReadFull(server, received[:]); err != nil {
					t.Fatalf("active session stopped at message %d: %v", i, err)
				}
				if err := <-writeDone; err != nil {
					t.Fatal(err)
				}
				if string(received[:]) != "active" {
					t.Fatalf("unexpected data: %q", received)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if time.Since(started) <= 2*idle {
				t.Fatal("test traffic did not outlive the original fixed deadline")
			}
			select {
			case <-done:
				t.Fatal("one-way activity must keep the whole relay alive")
			default:
			}
		})
	}
}

func TestRelayClosesIdleSession(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		t.Run(fmt.Sprintf("datagram=%t", datagram), func(t *testing.T) {
			_, server, _, done := relayPair(t, datagram, 80*time.Millisecond)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("idle relay remained open")
			}
			server.SetReadDeadline(time.Now().Add(time.Second))
			var data [1]byte
			if _, err := server.Read(data[:]); err == nil {
				t.Fatal("idle peer must be closed")
			}
		})
	}
}

func TestRelayStopsOnCancel(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		t.Run(fmt.Sprintf("datagram=%t", datagram), func(t *testing.T) {
			_, _, cancel, done := relayPair(t, datagram, time.Minute)
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancel did not close relay")
			}
		})
	}
}

func TestRelayStopsOnPeerClose(t *testing.T) {
	for _, datagram := range []bool{false, true} {
		t.Run(fmt.Sprintf("datagram=%t", datagram), func(t *testing.T) {
			client, _, _, done := relayPair(t, datagram, 80*time.Millisecond)
			client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("closed peer did not release relay")
			}
		})
	}
}
