# PocketNet outbound contract

PocketNet embeds the guest IPv4 TCP/UDP stack and one selected proxy client in the same Windows process. It does not create host adapters, services, routes, system proxy settings or a second VM. Unsupported Ethernet protocols, IPv6 and private guest destinations remain blocked.

## Configuration

The existing SOCKS5 schema is unchanged. Hysteria2 uses:

```json
{
  "listen": "127.0.0.1:0",
  "dns_upstream": "1.1.1.1:53",
  "proxy": {
    "type": "hysteria2",
    "server": "192.0.2.10",
    "server_port": 443,
    "password": "AUTH",
    "tls_server_name": "proxy.example",
    "obfs_password": "OPTIONAL-SALAMANDER-PASSWORD"
  }
}
```

The server is a literal pinned IPv4 address with one fixed port. `tls_server_name` is an explicit ASCII DNS name or IPv4 certificate name; it is used for TLS verification, never host DNS resolution. Omit `obfs_password` when Salamander is disabled. Other obfuscators, port hopping, realm/STUN/UPnP options, insecure TLS and direct fallback cannot be selected by this schema. Unknown JSON fields are rejected.

Only the pinned UDP IP and port can be opened by the Hysteria2 host dialer. Guest TCP/UDP destinations are carried inside that authenticated tunnel. DNS uses TCP to the configured public DNS destination through the same outbound. TCP and UDP relay activity refreshes the whole session's idle timeout (10 minutes and 60 seconds respectively).

## Connection probe

`PocketNet.exe --config profile.json --probe` performs a TLS handshake with fixed `1.1.1.1:443`, certificate name `one.one.one.one`, through the selected outbound. The total deadline is 15 seconds. It does not start a guest stream listener or accept a target from the command line. A valid completed probe returns JSON and exit code 0:

```json
{"ok":true,"protocol":"hysteria2"}
```

Failure returns `ok:false`, the selected protocol and a fixed non-secret error string. It never prints the authentication password, obfuscation password or raw network exception. Invalid configuration and process errors remain command-line failures.

## TLS trust and sources

Both the Hysteria2 transport and the inner probe TLS handshake use an explicit pure-Go certificate pool. The bundled Mozilla PEM from curl avoids Windows CryptoAPI's possible AIA chain downloads outside the selected proxy. No Windows certificate store is changed. Local enterprise/private roots are not imported automatically; the pinned public CA bundle needs deliberate updates with the program.

- Bundle: `certificates/cacert.pem`, Mozilla data dated 2026-10-20, [official source](https://curl.se/docs/caextract.html).
- SHA256: `796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`; source metadata and MPL 2.0 license are beside the PEM.
- [sing-quic](https://github.com/SagerNet/sing-quic/tree/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876): `v0.7.2-0.20261002084117-75c3ac4fa12b`, compatible with the existing sing pin.
- QUIC transport: `github.com/sagernet/quic-go v0.61.0-sing-box-mod.9`.
- `go.mod`/`go.sum` pin all dependencies. `licenses/MODULES.json` and adjacent license files cover the used Go modules; Go's license is included there as well.

`third_party/sing-quic` contains only the eight required upstream packages, original license and module metadata. The single source patch adds `clientConn.CloseWrite()` to send a request FIN without cancelling response reads. Its exact upstream source hashes and patch description are included. The local adapter normalizes wrapped EOF to Go's `io.EOF` and eagerly sends the destination so server-first protocols can reply before receiving application data.

## Checks

`go test -count=1 ./...` includes a real local Hysteria2 server with an ephemeral test CA, TCP/UDP/DNS/TLS, Salamander, server-first TCP, request half-close, authentication/certificate rejection, upstream loss and pinned host-dialer rejection. The test CA is generated in memory and is not trusted by the production constructor. Existing SOCKS5, flow cleanup and idle-timeout regressions remain in the same suite.

The local fixture does not use a user profile or an external VPS. Live guest/VPS checks belong to the integrating application. Hysteria2's upstream datagram size limits still apply; unsupported traffic has no alternative direct path.
