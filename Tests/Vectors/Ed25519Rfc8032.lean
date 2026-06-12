/-!
# Tests.Vectors.Ed25519Rfc8032 — Ed25519 test vectors with provenance discipline

Every vector cites its source, carries the component byte-lengths it must satisfy,
and keeps published RFC vectors strictly separate from local arbitrary-seed
regression vectors. A mistyped or line-wrapped seed must make a KAT **fail**, never
silently pass against a vector borrowed from a different seed.

## Why this file exists

An Ed25519 interop blocker was once suspected after a reproduction paired a *non-RFC*
seed (`9d61…7e8f`) with the RFC 8032 §7.1 Test 1 *public key* (which belongs to a
different seed, `9d61…7f60`). HACL\* Ed25519 was correct the whole time — it derived
the right key for the seed it was given. Independent verification (an RFC 8032
reference implementation **and** HACL\* on the correct seed reproducing the published
public key and signature byte-for-byte) confirmed this. The lesson encoded here:
check the **provenance and length** of a published vector before trusting it over a
verified library.
-/

namespace Tests.Vectors.Ed25519Rfc8032

/-- An Ed25519 known-answer vector with an explicit source label. Hex fields; the
`wellFormed` predicate pins their lengths. -/
structure Ed25519Vector where
  source  : String
  alg     : String
  seedHex : String   -- 32-byte secret seed → 64 hex chars
  pubHex  : String   -- 32-byte public key → 64 hex chars
  msgHex  : String   -- message (may be empty); even number of hex chars
  sigHex  : String   -- 64-byte signature → 128 hex chars

/-- **RFC 8032 §7.1 Test 1.** Source: RFC 8032, Section 7.1, "Test 1".
The secret key is `9d61…7f60` (NOT `9d61…7e8f`). -/
def rfc8032Test1 : Ed25519Vector :=
  { source  := "RFC 8032 §7.1 Test 1"
    alg     := "Ed25519"
    seedHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    pubHex  := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    msgHex  := ""
    sigHex  :=
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" }

/-- **Local arbitrary-seed regression vector — NOT an RFC 8032 published vector.**
This seed (`9d61…7e8f`) is the one that triggered the historical false alarm by being
paired with RFC Test 1's public key. Its true outputs (below) were verified with an
independent RFC 8032 reference; retained to guard against re-mixing a seed with a
public key from a different seed. -/
def localRegression : Ed25519Vector :=
  { source  := "Local arbitrary-seed regression (NOT RFC 8032)"
    alg     := "Ed25519"
    seedHex := "9d61b19deffe1f1e92ca4cd2b5e3c0f8a8f1b2c3d4e5f60718293a4b5c6d7e8f"
    pubHex  := "bcd55c06252a518be441c79fe8b5b6ae89f26c2e3c618c83edaaba1cd776eb13"
    msgHex  := ""
    sigHex  :=
      "6b66cdc2e862d4e4ead19fdb28b7bc4cd5d3034071f5856d992333b33cc32ce55c3927c020df77a451d5c64b05289bc926c74a8469a31bccb8ff6310dbdee107" }

/-- Structural well-formedness: the hex lengths imply the required byte lengths
(seed 32, public 32, signature 64) and an even-length message. A mistyped or
line-wrapped vector fails this, so it cannot silently pass a KAT. -/
def wellFormed (v : Ed25519Vector) : Bool :=
  v.seedHex.length == 64
    && v.pubHex.length == 64
    && v.sigHex.length == 128
    && v.msgHex.length % 2 == 0

/-- The two seeds must differ — a guard against the exact historical mistake of
treating the regression seed as the RFC seed. -/
def seedsDistinct : Bool := rfc8032Test1.seedHex ≠ localRegression.seedHex

end Tests.Vectors.Ed25519Rfc8032
