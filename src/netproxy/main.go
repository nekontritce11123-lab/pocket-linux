package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
)

func run() error {
	path := flag.String("config", "", "explicit proxy configuration")
	probe := flag.Bool("probe", false, "verify a fixed public TLS endpoint through the selected proxy")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("usage: PocketNet.exe --config path.json [--probe]")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if err != nil {
		return err
	}
	c, err := parseConfig(data)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *probe {
		return runProbe(ctx, c, os.Stdout)
	}
	listener, err := net.Listen("tcp4", c.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "READY", "listen": listener.Addr().String(), "proxy_type": c.Proxy.Type, "direct_fallback": false})
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	listener.Close()
	err = serveGuest(ctx, conn, c)
	if err == io.EOF || ctx.Err() != nil {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PocketNet:", err)
		os.Exit(1)
	}
}
