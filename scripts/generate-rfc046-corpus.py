#!/usr/bin/env python3
"""Regenerate RFC 046's public, deterministic hostile parser corpus."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "testdata" / "fuzz" / "clienthello"


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def vector16(data: bytes) -> bytes:
    return u16(len(data)) + data


def extension(kind: int, data: bytes) -> bytes:
    return u16(kind) + vector16(data)


def sni(names: list[tuple[int, bytes]]) -> bytes:
    entries = b"".join(bytes([kind]) + vector16(name) for kind, name in names)
    return vector16(entries)


SUPPORTED_VERSIONS = extension(43, b"\x02\x03\x04")
SUPPORTED_GROUPS = extension(10, b"\x00\x02\x00\x1d")
SIGNATURES = extension(13, b"\x00\x02\x08\x07")
X25519_ENTRY = b"\x00\x1d" + vector16(bytes([7]) * 32)
KEY_SHARE = extension(51, vector16(X25519_ENTRY))


def clienthello(
    suites: bytes = b"\x13\x01",
    extensions: bytes = SUPPORTED_VERSIONS + SUPPORTED_GROUPS + KEY_SHARE + SIGNATURES,
) -> bytes:
    body = (
        b"\x03\x03"
        + bytes([0xAB]) * 32
        + b"\x00"
        + vector16(suites)
        + b"\x01\x00"
        + vector16(extensions)
    )
    return b"\x01" + u24(len(body)) + body


valid = clienthello()
underdeclared = valid[:1] + u24(len(valid) - 5) + valid[4:]

grease_groups = extension(10, b"\x00\x04\x0a\x0a\x00\x1d")
grease_signatures = extension(13, b"\x00\x04\x0a\x0a\x08\x07")
grease_entry = b"\x0a\x0a\x00\x01\xaa"
grease_keyshare = extension(51, vector16(grease_entry + X25519_ENTRY))
unknown_extension = extension(0xFAFA, b"\x01")
grease_clienthello = clienthello(
    b"\x0a\x0a\x13\x01",
    SUPPORTED_VERSIONS
    + grease_groups
    + grease_keyshare
    + grease_signatures
    + unknown_extension,
)

too_many_extensions = clienthello(
    extensions=SUPPORTED_VERSIONS
    + SUPPORTED_GROUPS
    + KEY_SHARE
    + SIGNATURES
    + extension(0xFAFA, b"") * 65
)

label63 = b"a" * 63
label64 = b"a" * 64
name253 = b".".join([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61])
name254 = b".".join([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 62])

SEEDS = {
    "accept-valid-clienthello.bin": valid,
    "accept-grease-cross-layer-clienthello.bin": grease_clienthello,
    "reject-handshake-underdeclared.bin": underdeclared,
    "reject-handshake-final-residue.bin": valid + b"\x99",
    "reject-semantic-unknown-suite.bin": clienthello(b"\x0a\x0a"),
    "reject-extension-count-budget.bin": too_many_extensions,
    "accept-supported-versions-grease.bin": b"\x04\x0a\x0a\x03\x04",
    "reject-supported-versions-odd.bin": b"\x03\x03\x04\x00",
    "accept-supported-groups-grease.bin": b"\x00\x04\x0a\x0a\x00\x1d",
    "reject-signature-algorithms-empty.bin": b"\x00\x00",
    "accept-keyshare-grease.bin": vector16(grease_entry),
    "reject-keyshare-empty-unknown.bin": b"\x00\x04\x0a\x0a\x00\x00",
    "accept-sni-mixed-known-unknown.bin": sni([(1, b"x"), (0, b"A.EXAMPLE")]),
    "reject-sni-empty-list.bin": b"\x00\x00",
    "reject-sni-empty-name.bin": b"\x00\x03\x00\x00\x00",
    "reject-sni-control-default-route.bin": sni([(0, b"a\x00b")]),
    "reject-sni-reserved-ldh.bin": sni([(0, b"ab--bad")]),
    "accept-sni-label-63.bin": sni([(0, label63)]),
    "reject-sni-label-64.bin": sni([(0, label64)]),
    "accept-sni-name-253.bin": sni([(0, name253)]),
    "reject-sni-name-254.bin": sni([(0, name254)]),
    "accept-alpn-opaque-order.bin": b"\x00\x0c\x02h2\x08http/1.1",
    "reject-alpn-inner-residue.bin": b"\x00\x04\x02h2\x99",
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for existing in OUT.glob("*.bin"):
        existing.unlink()
    for name, data in sorted(SEEDS.items()):
        (OUT / name).write_bytes(data)
    print(f"wrote {len(SEEDS)} RFC 046 corpus seeds to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
