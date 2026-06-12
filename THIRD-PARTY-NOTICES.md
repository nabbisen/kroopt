# Third-Party Notices

kroopt is licensed under Apache-2.0 (see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE)). It redistributes the following third-party code in source
form. Each component keeps its own license and its upstream copyright headers
unmodified.

## HACL\* (Project Everest) — vendored under `Kroopt/Native/hacl/`

A portable-C subset of [HACL\*](https://github.com/hacl-star/hacl-star),
obtained via the `hacl-star` OCaml package, version **0.4.5**. It is the native
cryptographic backend for the v0.3 binding (see
[`docs/src/native-crypto.md`](docs/src/native-crypto.md)).

| What | License | Files |
|------|---------|-------|
| HACL\* generated C primitives | **MIT** — Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation | `Hacl_*.c`, `Hacl_*.h`, `Lib_Memzero0.c`, `internal/*.h` |
| KaRaMeL / kremlin runtime headers | **Apache-2.0** — Copyright (c) INRIA and Microsoft Corporation | `include/kremlin/**`, `minimal/*.h` |

* **Scope.** Only the primitives `TLS_CHACHA20_POLY1305_SHA256` needs with X25519
  and Ed25519: SHA-256/384, X25519, ChaCha20-Poly1305, HKDF/HMAC-SHA256, Ed25519.
  No vale assembly and no EverCrypt dispatch layer are vendored.
* **Modifications.** None. The files are redistributed verbatim with their
  license headers retained. The full license texts are reproduced in
  [`Kroopt/Native/hacl/LICENSE`](Kroopt/Native/hacl/LICENSE). This was verified
  in M20: `Hacl_Ed25519.c` and its dependencies are byte-identical (`diff` = 0) to
  the pristine 0.4.5 release at tag `ocaml-v0.4.5`.
* **Known issue — Ed25519 (tracked).** The vendored 0.4.5 `dist/gcc-compatible`
  Ed25519 produces self-consistent but **non-RFC-8032** output in this environment
  (reproduced in standalone C at every optimisation level, so it is not the FFI,
  optimisation, or strict aliasing — see [`docs/src/provisioning.md`](docs/src/provisioning.md)).
  SHA-256/384/512 (FIPS 180-4) and X25519 (RFC 7748) are confirmed correct. The
  remediation is to re-vendor a known-correct Ed25519 unit (a newer HACL release),
  KAT-validated against RFC 8032 before integration; a tripwire in
  `kroopt-provision-test` guards the seam meanwhile. Ed25519 is therefore **not yet
  interop-ready**; the ChaCha20-Poly1305 / X25519 / SHA-256 record and key-schedule
  paths are unaffected.
* **Compatibility.** MIT and Apache-2.0 are both permissive and compatible with
  kroopt's Apache-2.0 license.
* **kroopt's own glue.** `Kroopt/Native/kroopt_ffi.c` is kroopt's own code
  (Apache-2.0), not part of HACL\*; it only marshals byte buffers across the FFI.

If you prefer not to carry vendored sources in-tree, the same build works against
a pinned HACL\* checkout (git submodule / fetch step) or a system `libevercrypt`;
the vendored copy is provided so the build is self-contained and offline-
reproducible.
