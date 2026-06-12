# Third-Party Notices

kroopt is licensed under Apache-2.0 (see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE)). It redistributes the following third-party code in source
form. Each component keeps its own license and its upstream copyright headers
unmodified.

## HACL\* (Project Everest) — vendored under `Kroopt/Native/hacl/`

A portable-C subset of [HACL\*](https://github.com/hacl-star/hacl-star),
obtained via the `hacl-star` OCaml package, version **0.4.5**. It is the native
cryptographic backend for the v0.3 binding (see
[`docs/src/crypto/native-crypto.md`](docs/src/crypto/native-crypto.md)).

| What | License | Files |
|------|---------|-------|
| HACL\* generated C primitives | **MIT** — Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation | `Hacl_*.c`, `Hacl_*.h`, `Lib_Memzero0.c`, `internal/*.h` |
| KaRaMeL / kremlin runtime headers | **Apache-2.0** — Copyright (c) INRIA and Microsoft Corporation | `include/kremlin/**`, `minimal/*.h` |

* **Scope.** Only the primitives `TLS_CHACHA20_POLY1305_SHA256` needs with X25519
  and Ed25519: SHA-256/384, X25519, ChaCha20-Poly1305, HKDF/HMAC-SHA256, Ed25519.
  No vale assembly and no EverCrypt dispatch layer are vendored.
* **Modifications.** None. The files are redistributed verbatim with their
  license headers retained. The full license texts are reproduced in
  [`Kroopt/Native/hacl/LICENSE`](Kroopt/Native/hacl/LICENSE). This was verified:
  `Hacl_Ed25519.c` and its dependencies are byte-identical (`diff` = 0) to the
  pristine 0.4.5 release at tag `ocaml-v0.4.5`.
* **Ed25519 status.** HACL\* Ed25519 reproduces the RFC 8032 §7.1 Test 1 vectors
  byte-for-byte and interoperates with OpenSSL on the TLS 1.3 `CertificateVerify`
  construction (`scripts/ed25519-interop.sh`); SHA-256/384/512 (FIPS 180-4) and
  X25519 (RFC 7748) are likewise confirmed. (A 2026-06 report of a non-RFC Ed25519
  defect was a test-vector provisioning error — a non-RFC seed paired with RFC Test
  1's public key — not a HACL\* defect; see [`docs/src/crypto/provisioning.md`](docs/src/crypto/provisioning.md).)
* **Compatibility.** MIT and Apache-2.0 are both permissive and compatible with
  kroopt's Apache-2.0 license.
* **kroopt's own glue.** `Kroopt/Native/kroopt_ffi.c` is kroopt's own code
  (Apache-2.0), not part of HACL\*; it only marshals byte buffers across the FFI.

If you prefer not to carry vendored sources in-tree, the same build works against
a pinned HACL\* checkout (git submodule / fetch step) or a system `libevercrypt`;
the vendored copy is provided so the build is self-contained and offline-
reproducible.
