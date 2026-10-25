package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
)

type config struct {
	Listen      string      `json:"listen"`
	DNSUpstream string      `json:"dns_upstream"`
	Proxy       proxyConfig `json:"proxy"`
}

type proxyConfig struct {
	Type          string `json:"type"`
	Server        string `json:"server"`
	ServerPort    uint16 `json:"server_port"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	ObfsPassword  string `json:"obfs_password,omitempty"`
}

func parseConfig(data []byte) (config, error) {
	var c config
	if len(data) > 65536 {
		return c, errors.New("configuration too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing configuration")
	}
	listen, err := netip.ParseAddrPort(c.Listen)
	if err != nil || listen.Addr() != netip.MustParseAddr("127.0.0.1") {
		return c, errors.New("listen must be IPv4 loopback")
	}
	server, err := netip.ParseAddr(c.Proxy.Server)
	if err != nil || !server.Is4() || server.IsUnspecified() || server.IsMulticast() || c.Proxy.ServerPort == 0 {
		return c, errors.New("proxy must have a pinned IPv4 address and port")
	}
	switch c.Proxy.Type {
	case "socks5":
		if c.Proxy.TLSServerName != "" || c.Proxy.ObfsPassword != "" {
			return c, errors.New("Hysteria2 fields are not valid for SOCKS5")
		}
	case "http", "https":
		if c.Proxy.ObfsPassword != "" || len(c.Proxy.Username) > 4096 || len(c.Proxy.Password) > 4096 || strings.Contains(c.Proxy.Username, ":") {
			return c, errors.New("invalid CONNECT proxy credentials or options")
		}
		if c.Proxy.Type == "https" && !validServerName(c.Proxy.TLSServerName) {
			return c, errors.New("HTTPS requires an explicit TLS server name")
		}
		if c.Proxy.Type == "http" && c.Proxy.TLSServerName != "" {
			return c, errors.New("TLS server name is not valid for HTTP")
		}
	case "hysteria2":
		if c.Proxy.Username != "" || c.Proxy.Password == "" || len(c.Proxy.Password) > 4096 {
			return c, errors.New("Hysteria2 requires a password and no username")
		}
		if !validServerName(c.Proxy.TLSServerName) {
			return c, errors.New("Hysteria2 requires an explicit TLS server name")
		}
		if c.Proxy.ObfsPassword != "" && (len(c.Proxy.ObfsPassword) < 4 || len(c.Proxy.ObfsPassword) > 4096) {
			return c, errors.New("invalid Salamander password length")
		}
	default:
		return c, errors.New("an explicit SOCKS5, HTTP, HTTPS or Hysteria2 proxy is required")
	}
	if !allowedDestination(c.DNSUpstream) {
		return c, errors.New("DNS must be an explicit public IPv4 destination through the proxy")
	}
	return c, nil
}

func validServerName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if address, err := netip.ParseAddr(name); err == nil {
		return address.Is4()
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, letter := range label {
			if letter != '-' && !(letter >= 'a' && letter <= 'z') && !(letter >= 'A' && letter <= 'Z') && !(letter >= '0' && letter <= '9') {
				return false
			}
		}
	}
	return true
}

func allowedDestination(address string) bool {
	a, err := netip.ParseAddrPort(address)
	if err != nil || a.Port() == 0 {
		return false
	}
	ip := a.Addr()
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
