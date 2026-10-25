package main

import (
	"strings"
	"testing"
)

const validConfig = `{"listen":"127.0.0.1:0","dns_upstream":"198.18.0.53:53","proxy":{"type":"socks5","server":"127.0.0.1","server_port":1080}}`

func TestConfigRequiresAnExplicitPinnedProxy(t *testing.T) {
	if _, err := parseConfig([]byte(validConfig)); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`{}`, strings.Replace(validConfig, `"socks5"`, `"direct"`, 1),
		strings.Replace(validConfig, `"server":"127.0.0.1"`, `"server":"example.com"`, 1),
		strings.Replace(validConfig, `"server_port":1080`, `"server_port":0`, 1),
		strings.Replace(validConfig, `"listen":"127.0.0.1:0"`, `"listen":"0.0.0.0:1080"`, 1),
		strings.Replace(validConfig, `"proxy":{`, `"fallback":"direct","proxy":{`, 1),
		validConfig + `{}`, strings.Repeat(" ", 65537),
	} {
		if _, err := parseConfig([]byte(text)); err == nil {
			t.Fatalf("unsafe config accepted: %.100s", text)
		}
	}
}

func TestGuestDestinationsCannotBecomeHostOrLANConnections(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "192.168.0.2:80", "169.254.169.254:80", "10.0.2.2:53", "[::1]:80", "0.0.0.0:80", "224.0.0.1:80", "255.255.255.255:80"} {
		if allowedDestination(addr) {
			t.Errorf("host/private destination accepted: %s", addr)
		}
	}
	for _, addr := range []string{"198.18.0.10:18080", "1.1.1.1:443"} {
		if !allowedDestination(addr) {
			t.Errorf("public destination rejected: %s", addr)
		}
	}
}
