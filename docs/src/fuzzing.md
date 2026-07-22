# Parser fuzzing and hostile corpus

The canonical parser fuzz gate combines two complementary checks:

```sh
lake exe kroopt-parse-fuzz 20000
```

First, it loads the committed RFC-046 corpus from
`testdata/fuzz/clienthello/manifest.tsv`. Then it runs the bounded deterministic
pseudorandom smoke loop over reader, vector, record, and ClientHello surfaces.
The success marker is printed only after both layers pass.

## Classification manifest

The manifest has five fixed tab-separated columns:

```text
file  target  outcome  internal_error  public_error
```

Targets are stable wrappers for `clienthello`, `supported_versions`,
`supported_groups`, `signature_algorithms`, `key_share`, `sni`, and `alpn`.
Separate nested targets are intentional: a well-framed GREASE-only vector can
be structurally accepted even when a complete ClientHello would later fail for
lack of a usable semantic offer.

The loader fails closed on a missing manifest, malformed row, duplicate name,
unknown target or outcome, missing/extra `.bin` file, seed above the live
65,536-byte reassembly ceiling, changed internal/public error class, or a
successful ClientHello whose `WireBound.wireBytes` differ from its input.
Failure output names the fixture but never prints its hostile contents.

## Corpus and mutation policy

Committed seeds are minimized and behavior-named. They cover exact top-level
framing, nested list framing, semantic no-overlap, item-count exhaustion,
cross-layer GREASE tolerance, key-share emptiness, ALPN residue, and the
constrained SNI grammar—including empty names/lists, mixed known/unknown types,
reserved LDH labels, control bytes, and the 63/64-label and 253/254-name
boundaries.

The executable also generates bounded representatives of three mutation
families on every run:

- classification-preserving known/GREASE reorder or insertion;
- structural length, truncation, and residue damage;
- exactly framed semantic replacement of all usable suites.

Pseudorandom successes additionally check exact public input binding and the
decoded ClientHello header/body-size relationship. Fuzzing complements rather
than replaces the Lean bounds and exact-consumption proofs.

The corpus contains only public protocol bytes. New crash, allocation,
classification, or state-safety regressions must be minimized, added to the
manifest, and linked to the owning RFC.
