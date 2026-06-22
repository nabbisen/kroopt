# Constrained vs browser-grade interop

kroopt's interoperability is delivered in two tiers, and the line between them is drawn
deliberately. The same discipline that separates PROVEN / TESTED / ASSUMED / OUTSCOPE in the crypto
trust boundary applies to interop claims: kroopt states *constrained* interop as what it tests today,
and treats *browser-grade* interop as a later goal it does not yet claim. This page records exactly
where that line falls, so a reader never mistakes an aspiration for a guarantee.

## Constrained interop — tested today

This is the profile kroopt commits to and exercises in its live interop harness and offline replay
corpus:

- **TLS 1.3 server role only** (RFC 8446), on **separate listeners** for plaintext and TLS — no
  same-port sniffing.
- **No HelloRetryRequest.** The client must present an initial `key_share` in a group kroopt
  supports; a ClientHello whose only `key_share` is in an unsupported group fails cleanly rather than
  triggering a retry.
- **Wired primitives:** suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
  `TLS_CHACHA20_POLY1305_SHA256`; groups x25519 and secp256r1 (P-256); signatures Ed25519,
  ECDSA-P256, and RSA-PSS (as the configured leaf allows).
- **Three independent live clients:** `openssl s_client`, Python `ssl`, and `curl`, against both the
  blocking and the non-blocking reactor driver. The harness exercises the full constrained behaviour
  set — handshake, application-data exchange, an explicitly-observed **graceful `close_notify`**
  (RFC 8446 §6.1), and a **rejection** case (an x25519-only listener refusing a P-256-forced client).
- **GREASE tolerance (RFC 8701).** Unknown/reserved values that appear *alongside* valid ones are
  ignored. This is tested specifically for a GREASE **named group** (`0x0a0a`) alongside x25519 and a
  GREASE **cipher suite** (`0x0a0a`) before a supported suite: in both cases the valid value is
  selected and the handshake completes. A ClientHello offering *only* an unknown group is rejected —
  "alongside valid" is the tolerated case, and it is the only GREASE shape currently tested.
- **Offline corpus.** A committed captured-ClientHello corpus (constrained + broad + malformed)
  replays deterministically through the pure/fake path, catching negotiation and parsing regressions
  without a live socket.

On ALPN: the curl scenario drives a real HTTPS request/response and the graceful close, but ALPN is
reported as connection **metadata only**. This is not an end-to-end HTTP/2 claim.

## Browser-grade interop — not yet claimed

Reaching real browsers (Chrome, Firefox, Safari, across platforms) is a later goal — RFC 035
(browser-grade crypto surface), RFC 026 (interop breadth), and the RFC 038 constrained-interop
follow-ons. It is **explicitly not claimed today**, and it adds, beyond the constrained profile:

- **Real browser ClientHello diversity:** larger ClientHellos, more extensions, and GREASE across all
  fields. Only named-group and cipher-suite GREASE *alongside valid values* are tested today; GREASE
  in other positions, and large-CH edge handling, are unverified.
- **HTTP/2 end-to-end:** h2 negotiated *and* an HTTP/2 exchange completed by the stack above kroopt.
  Today ALPN is observation-only.
- **Graceful decline of unsupported offers:** browsers may attempt session tickets or early data;
  these must be ignored cleanly. kroopt's policy forbids them, but a real-browser decline path is not
  yet validated.
- **The no-HRR caveat:** a browser configured to lead with a `key_share` only in a group kroopt does
  not support (a P-256-only or post-quantum-first `key_share`) would fail rather than retry. Ordinary
  browsers offer an x25519 `key_share` up front, so this is rare in practice — but it is a real
  limitation a browser-grade profile must address (HelloRetryRequest is out of scope until a later
  RFC).
- **A documented browser test matrix** across engines and platforms.

Until a committed browser run exists, kroopt claims constrained interop only. The constrained profile
above is what the trust/test matrix backs; everything in this section is roadmap, not guarantee.
