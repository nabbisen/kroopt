# Vendored crypto: provenance and licensing

> **Capability note.** For the authoritative current capability and security posture, see
> [current security state](../verification/current-security-state.md). Specific suite / group /
> signature mentions or "pending"/"deferred" wording on this page may predate the current capability
> matrix and are superseded there.


kroopt is licensed under **Apache-2.0**. To make the native crypto build
self-contained and offline-reproducible, it **vendors** a portable-C subset of
[HACL\*](https://github.com/hacl-star/hacl-star) (Project Everest) under
`Kroopt/Native/hacl/`. This page records what is vendored and under what terms,
so the fact is declared plainly rather than buried in file headers.

## What is vendored

Obtained via the `hacl-star` OCaml package, **version 0.4.5**, vendored verbatim under
`Kroopt/Native/hacl/`. The vendored subset now covers every primitive the advertised constrained
profile needs end-to-end: SHA-2 (256/384/512), HMAC and HKDF, ChaCha20-Poly1305, X25519
(Curve25519), Ed25519, P-256 (ECDH + ECDSA), and RSA-PSS, **plus** the EverCrypt AEAD dispatch layer
(`EverCrypt_AEAD`, `EverCrypt_AutoConfig2`) and the **Vale verified assembly** for AES-GCM
(`aesgcm-x86_64-linux.S`, with `cpuid-x86_64-linux.S` for ISA detection), together with the
KaRaMeL/kremlin runtime headers those sources include. (An earlier revision of this page predated the
AES-GCM/Vale/EverCrypt and P-256/RSA-PSS additions — see
[current security state](../verification/current-security-state.md) for the authoritative matrix.)

### Cryptographic provenance

> **✓ Provenance status — byte-level anchor recorded.** The "version 0.4.5" attribution is now backed by a
> byte-level identity anchor: the vendored sources are byte-identical to the named upstream artifact
> `hacl-star.0.4.5.tar.gz` (release tag `ocaml-v0.4.5`, sha256 `47bf253f…05e174`, corroborated by
> `ocaml/opam-repository`). 166 upstream files match with zero local modifications; the per-file record and
> `source_tree_sha256` (`ff82d9a7…daf1cd`) live in
> [`Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json`](../../../Kroopt/Native/hacl-provenance/HACL-PROVENANCE.json) (see [VENDOR.md](../../../Kroopt/Native/hacl-provenance/VENDOR.md))
> and are re-checked every build by the offline `scripts/check-hacl-provenance.sh` gate (with on-demand
> online re-verification via `scripts/verify-hacl-upstream.sh`). "Vendored verbatim" is therefore an
> established byte-level fact for this subset, not merely an intent. The KreMLin-318b7fa8 marker sits inside
> a header that itself byte-matched upstream, so it is corroborated by the match.

What each primitive is, where it comes from, and how it is exercised. "Advertised" means the real
provider lists it in `realCapabilities`, so a config may select it; "bound only" means the FFI and
signing code exist but the primitive is **not** advertised and a config requiring it is rejected at
validation.

| Primitive | Implementation (HACL\* 0.4.5) | Vendored | KAT vector | Live wire interop | Constant-time |
|---|---|---|---|---|---|
| AES-128/256-GCM | `EverCrypt_AEAD` + Vale verified asm | yes | NIST GCM Test Case 4 | not yet (wire uses ChaCha20) | ASSUMED (Vale/HACL\*) |
| ChaCha20-Poly1305 | `Hacl_Chacha20Poly1305_32` | yes | RFC 8439 round-trip + tamper | yes (openssl/python/curl) | ASSUMED |
| X25519 | `Hacl_Curve25519_51` | yes | RFC 7748 §6.1 | yes | ASSUMED |
| P-256 ECDH | `Hacl_P256` (`ecp256dh`) | yes | NIST CAVP KAS ECC-CDH | yes | ASSUMED |
| SHA-256 / SHA-384 | `Hacl_Hash_SHA2` | yes | FIPS 180-4 (one-block "abc") | via handshake | ASSUMED |
| HKDF-SHA-256 | `Hacl_HKDF` | yes | RFC 5869 §A.1 | via handshake | ASSUMED |
| HMAC-SHA-256/384 | `Hacl_HMAC` | yes | RFC 4231 §4.2 | via handshake | ASSUMED |
| Ed25519 sign/verify | `Hacl_Ed25519` | yes | RFC 8032 vectors | yes (server cert) | ASSUMED |
| ECDSA-P256 sign/verify | `Hacl_P256` (`ecdsa`) | yes | — (bound only) | — (not advertised) | ASSUMED |
| RSA-PSS sign/verify | `Hacl_RSAPSS` | yes | — (bound only) | — (not advertised) | ASSUMED |
| Randomness | OS CSPRNG (`getrandom`), **not** HACL\* | n/a | n/a | via handshake | OS entropy ASSUMED |

The known-answer tests run **through Lean over the FFI** (suite `kroopt-hacl-test`, 56 checks); the
native shim is built under AddressSanitizer + UndefinedBehaviorSanitizer (`scripts/sanitizer-check.sh`,
system gcc). Build flags for the vendored C are `-std=c11 -O2 -fPIC -fwrapv -D_GNU_SOURCE
-ffunction-sections -fdata-sections`; the AES-GCM path adds `-DHACL_CAN_COMPILE_VALE=1
-DHACL_CAN_COMPILE_VEC128 -DHACL_CAN_COMPILE_VEC256` and links the two `.S` objects. `-fwrapv` keeps
HACL\*'s defined wraparound from tripping UBSan's signed-overflow check.

**Known unsupported** (rejected at validation, by design — see
[deferred scope](../verification/deferred-scope.md)): TLS 1.2 / DTLS / QUIC suites, AES-CCM, X448,
P-384/P-521, and ECDSA-P256 / RSA-PSS *as advertised certificate signature schemes* (bound but not yet
servable).

## Licenses

| Component | License | Copyright |
|---|---|---|
| HACL\* generated C (`Hacl_*.c/.h`, `EverCrypt_*.c/.h`, `Lib_Memzero0.c`, `internal/*.h`) | MIT | (c) 2016-2020 INRIA, CMU and Microsoft Corporation |
| KaRaMeL/kremlin headers (`include/kremlin/**`, `minimal/*.h`) | Apache-2.0 | (c) INRIA and Microsoft Corporation |
| Vale verified assembly (`aesgcm-x86_64-linux.S`, `cpuid-x86_64-linux.S`) | Apache-2.0 | (c) INRIA and Microsoft Corporation (Project Everest) |

The MIT row includes the `EverCrypt_*` dispatch sources (verified per-file MIT header, identical to the
other generated C). The Vale `.S` assembly files carry **no per-file header**: per the
[HACL\* README](https://github.com/hacl-star/hacl-star), the whole repository is released under
Apache-2.0 and the *generated C* is additionally available under MIT, so the MIT carve-out does not
reach the Vale assembly (it is not generated C) — it is taken under the repository-default **Apache-2.0**,
the same license as kroopt. The vendored `Kroopt/Native/hacl/LICENSE`, the repository-root `NOTICE`, and
`THIRD-PARTY-NOTICES.md` have been refreshed to record EverCrypt (MIT) and the Vale assembly (Apache-2.0)
and to drop the earlier stale "no vale/EverCrypt" note.

Both are permissive and compatible with kroopt's Apache-2.0. The files are
redistributed **verbatim** with their per-file license headers retained; kroopt
introduces no modifications to the vendored algorithm sources (zero-modification is
the vendoring rule, and byte-level identity to the pinned upstream `ocaml-v0.4.5`
artifact is recorded and gate-checked — see the provenance note above). The MIT requirement — that the copyright and
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
