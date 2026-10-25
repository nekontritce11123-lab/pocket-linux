package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const probeDestination = "1.1.1.1:443"
const probeServerName = "one.one.one.one"

type probeResult struct {
	OK       bool   `json:"ok"`
	Protocol string `json:"protocol"`
	Error    string `json:"error,omitempty"`
}

func probeOutbound(ctx context.Context, proxy outboundProxy, destination string, tlsConfig *tls.Config) error {
	conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr(destination))
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	return tls.Client(conn, tlsConfig).HandshakeContext(ctx)
}

func runProbe(parent context.Context, c config, output io.Writer) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	result := probeResult{Protocol: c.Proxy.Type}
	proxy, err := newProxy(ctx, c)
	if err == nil {
		defer proxy.Close()
		roots, rootsErr := trustedRoots()
		if rootsErr != nil {
			err = rootsErr
		} else {
			err = probeOutbound(ctx, proxy, probeDestination, &tls.Config{ServerName: probeServerName, RootCAs: roots, MinVersion: tls.VersionTLS12})
		}
	}
	result.OK = err == nil
	if err != nil {
		result.Error = "Не удалось подтвердить защищённое подключение через прокси."
	}
	return json.NewEncoder(output).Encode(result)
}
