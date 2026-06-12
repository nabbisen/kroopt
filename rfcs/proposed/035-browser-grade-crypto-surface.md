# RFC 035 — Browser-Grade Crypto Surface (Deferred)

**Project.** kroopt  
**Status.** Proposed (deferred — do not start until M36/M37/M38 are green)  
**Type.** Implementation RFC  
**Target milestone.** Post-M38 (a descendant of RFC 016)  
**Depends on.** RFC 008/009 (crypto provider + shim), RFC 031/032/033/034 (correspondence + real-client handshake + capability honesty), RFC 037 (native hardening), RFC 015/026/036 (constrained interop)  
**Touches.** `Kroopt/Native/*` (vendored HACL\* surface), `Kroopt/Crypto/*`, the trust/proof/test matrix, the cert/auth story  
**Canonical source.** kroopt fixed requirements §3.3, §9; architect reviews of 2026-06-12 (crypto-scope decision).  

---

## 1. Summary and decision recorded

kroopt currently links a vendored HACL\* portable-C subset providing only
ChaCha20-Poly1305 / Ed25519 / X25519 / SHA-256, so it negotiates exactly
`TLS_CHACHA20_POLY1305_SHA256` with X25519 and an Ed25519 server certificate — a valid
TLS 1.3 configuration but a **constrained developer/server profile**, not a broad
browser/server compatibility profile.

**Decision (both architect reviews):** ship the constrained profile first and label it as
such; **do not** expand the crypto surface until M36 (correspondence), M37 (native
safety), and M38 (constrained OpenSSL/curl interop) are green. The current risk is
correspondence and live protocol execution, not algorithm breadth. This RFC records that
decision and scopes the eventual expansion; it is explicitly **not** to be started yet.

## 2. Milestone map (explicit)

- **M36** — production interpreter / correspondence (RFC 031/032/033) + capability/entropy
  honesty prelude (RFC 034);
- **M37** — native / budget / security hardening (RFC 037);
- **M38** — constrained OpenSSL/curl interop (RFC 015/026/036);
- **post-M38** — browser-grade crypto surface (this RFC).

## 3. Scope (when activated)

- `TLS_AES_128_GCM_SHA256` (and `TLS_AES_256_GCM_SHA384` if needed);
- P-256 (secp256r1) key exchange;
- ECDSA-P256 certificate signatures;
- RSA-PSS server signatures only if the certificate ecosystem requires it;
- per-algorithm KATs and an interop matrix;
- the trust/proof/test-matrix delta distinguishing **constrained** from **browser-grade**.

## 4. Certificate-ecosystem note

Browser-grade is not only AES-GCM/P-256 ciphers; it also requires a practical
public-certificate story, which today usually means **ECDSA-P256 or RSA** leaf/chain
certificates, not Ed25519. Ed25519 WebPKI/client support has improved but is not
universal. Keep Ed25519 as the **constrained/developer** profile until browser and
certificate-ecosystem evidence says otherwise; activating this RFC includes validating
the realistic cert/auth path, not only the cipher suite.

## 5. Trust-boundary expansion checklist (each added primitive)

- provenance of the added HACL\* units (which Project Everest sources, which build);
- a KAT for each primitive;
- cross-implementation interop (OpenSSL/Python, as for ChaCha/Ed25519);
- a sanitizer target covering the new shim surface;
- config-negotiation tests (the suite/group/scheme is selected and rejected correctly);
- an update to the proof/trust/test matrix and the constrained-vs-browser-grade labeling.

## 6. Non-goals and constraints

This RFC implements no primitive itself; it gates and scopes that work. It does not relax
the verification-first principle: any added primitive remains ASSUMED-verified (borrowed
from HACL\*/EverCrypt), never hand-rolled, never claimed as proven by kroopt. Marketing
must not call the constrained profile "browser-ready" until live browser/curl/OpenSSL
tests confirm it.

## 7. Activation gate

Activate only after: RFC 031/032/033/034 met (production interpreter, typed actions, real
protected-handshake processing, capability/entropy honesty); RFC 037 met (native safety,
budgets); and RFC 015/026/036 constrained interop green (constrained OpenSSL/curl
handshake with captured traces). Until then this RFC stays in `proposed/` as a recorded
decision and forward scope.
