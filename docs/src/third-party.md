# Vendored crypto: provenance and licensing

kroopt is licensed under **Apache-2.0**. To make the native crypto build
self-contained and offline-reproducible, it **vendors** a portable-C subset of
[HACL\*](https://github.com/hacl-star/hacl-star) (Project Everest) under
`Kroopt/Native/hacl/`. This page records what is vendored and under what terms,
so the fact is declared plainly rather than buried in file headers.

## What is vendored

Obtained via the `hacl-star` OCaml package, version **0.4.5**. Only the
primitives the `TLS_CHACHA20_POLY1305_SHA256` suite needs with X25519 and
Ed25519 are included: SHA-256/384, X25519, ChaCha20-Poly1305, HKDF/HMAC-SHA256,
and Ed25519, plus the KaRaMeL/kremlin runtime headers those sources include. No
vale assembly and no EverCrypt dispatch layer are vendored.

## Licenses

| Component | License | Copyright |
|---|---|---|
| HACL\* generated C (`Hacl_*.c/.h`, `Lib_Memzero0.c`, `internal/*.h`) | MIT | (c) 2016-2020 INRIA, CMU and Microsoft Corporation |
| KaRaMeL/kremlin headers (`include/kremlin/**`, `minimal/*.h`) | Apache-2.0 | (c) INRIA and Microsoft Corporation |

Both are permissive and compatible with kroopt's Apache-2.0. The files are
redistributed **verbatim** with their per-file license headers retained; kroopt
makes no modifications to them. The MIT requirement — that the copyright and
permission notice travel with the code — is met by those intact headers, and the
full texts are also reproduced in `Kroopt/Native/hacl/LICENSE`. A repository-root
[`THIRD-PARTY-NOTICES.md`](https://github.com/nabbisen/kroopt/blob/main/THIRD-PARTY-NOTICES.md)
and the `NOTICE` file carry the same declaration.

kroopt's own native code is just `Kroopt/Native/kroopt_ffi.c` (Apache-2.0), which
marshals byte buffers across the FFI and contains no cryptographic logic.

## Why vendored, and the alternatives

Vendoring keeps `lake build` self-contained and offline — no network fetch, no
system crypto dependency — which suits a verification-first, reproducible build.
The same build works equally against a pinned HACL\* checkout (git submodule or a
fetch step) or a system `libevercrypt`, for projects that prefer not to carry
third-party sources in-tree. The crypto math is borrowed and **assumed**-verified
(Project Everest); kroopt proves the protocol structure around it, never the
cryptography itself (see the proof/trust/test matrix).
