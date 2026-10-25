package main

import (
	"strings"
	"testing"
)

const validHysteriaConfig = `{"listen":"127.0.0.1:0","dns_upstream":"1.1.1.1:53","proxy":{"type":"hysteria2","server":"192.0.2.10","server_port":443,"password":"test-auth","tls_server_name":"proxy.example"}}`

func TestHysteriaConfigRequiresVerifiedTLSAndPinnedServer(t *testing.T) {
	if _, err := parseConfig([]byte(validHysteriaConfig)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig([]byte(strings.Replace(validHysteriaConfig, `"tls_server_name":"proxy.example"`, `"tls_server_name":"proxy.example","obfs_password":"test-salamander"`, 1))); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		strings.Replace(validHysteriaConfig, `"password":"test-auth"`, `"password":""`, 1),
		strings.Replace(validHysteriaConfig, `,"tls_server_name":"proxy.example"`, ``, 1),
		strings.Replace(validHysteriaConfig, `"proxy.example"`, `"https://proxy.example/"`, 1),
		strings.Replace(validHysteriaConfig, `"server":"192.0.2.10"`, `"server":"proxy.example"`, 1),
		strings.Replace(validHysteriaConfig, `"server_port":443`, `"server_port":0`, 1),
		strings.Replace(validHysteriaConfig, `"proxy":{`, `"proxy":{"insecure":true,`, 1),
		strings.Replace(validHysteriaConfig, `"proxy":{`, `"proxy":{"server_ports":[443,444],`, 1),
		strings.Replace(validHysteriaConfig, `"proxy":{`, `"proxy":{"username":"unexpected",`, 1),
		strings.Replace(validHysteriaConfig, `"proxy":{`, `"proxy":{"obfs_password":"x",`, 1),
	} {
		if _, err := parseConfig([]byte(text)); err == nil {
			t.Fatal("unsafe Hysteria2 configuration accepted")
		}
	}
	for _, field := range []string{`"tls_server_name":"proxy.example",`, `"obfs_password":"test-obfs",`} {
		if _, err := parseConfig([]byte(strings.Replace(validConfig, `"proxy":{`, `"proxy":{`+field, 1))); err == nil {
			t.Fatal("Hysteria2 fields silently accepted for SOCKS5")
		}
	}
}
