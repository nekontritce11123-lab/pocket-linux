# Local Hysteria2 half-close patch

Upstream: github.com/sagernet/sing-quic
Version: v0.7.2-0.20261002084117-75c3ac4fa12b
Commit: 75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876
Module checksum: h1:2Jx/URJAPt32MEbLmAR5nzH87tO6NQZLRfRFvFqBWuk=
Source: https://github.com/SagerNet/sing-quic/tree/75c3ac4fa12b4ded2dc01b392ed7d5eaf3ea6876

Only the packages required by hysteria2, their original licenses, go.mod and go.sum are included; upstream tests and unrelated protocols are omitted.

The only source change adds clientConn.CloseWrite(), forwarding to the embedded QUIC stream's Close(). It sends the request FIN while preserving response reads. Upstream clientConn.Close() also cancels reads, so it cannot implement a TCP half-close.

The local Hysteria2 fixture tests the request-FIN/response sequence. UPSTREAM-SHA256.json records every copied upstream file before the patch.
