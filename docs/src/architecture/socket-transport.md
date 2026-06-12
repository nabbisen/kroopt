# Records over a real OS socket

Until now kroopt's records were exchanged in memory. The `kroopt-socket-test`
harness (`Tests/SocketHandshake.lean`) exchanges a full TLS 1.3 server flight as real
`Kroopt.Conn.Record13` records over a **real OS socket** — an `AF_UNIX` socketpair —
confirming the sealed records survive real kernel I/O and open on the peer.

One fd plays the peer and the other kroopt. kroopt seals its flight (a cleartext
ServerHello record plus four ChaCha20-Poly1305 `TLSCiphertext` records for
EncryptedExtensions / Certificate / CertificateVerify / Finished, sequence numbers
0–3 under the server handshake-traffic key) and writes it to the socket; the peer
reads the records back, confirms they are `TLSCiphertext` (`0x17 0x03 0x03 …`), and
opens each one. The peer then seals a client Finished under the client
handshake-traffic key and writes it; kroopt reads and opens it. Finally application
data round-trips encrypted under the server application-traffic key. The record layer
is the production one; only the byte transport changed from memory to a socket.

## Scope and boundary

The socket helpers (`Kroopt/Native/kroopt_socket.c`) are **test-only**
transport-binding glue: a minimal socketpair plus blocking read/write/close, with no
protocol logic. kroopt's production core performs no syscalls and reaches the network
only through iotakt (RFC 010); this harness exists to exercise the transport boundary
from a test and to de-risk that binding. The remaining v0.3 work is the production
iotakt socket adapter and a live `openssl s_client` / `curl` handshake (RFC 015/026),
which run the same record layer over a real, non-blocking, externally-driven peer.
