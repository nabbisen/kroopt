# Canonical release-gate environment

This is the reproducible host contract for `scripts/gate.sh --profile full-release`. A missing or
out-of-range prerequisite is a gate failure, not a manually skipped check.

## Supported tool ranges

| Tool | Supported range / source | Used by |
|---|---|---|
| Lean / Lake | exact version pinned by `lean-toolchain` | build, proofs, suites, fuzz |
| mdBook | 0.5.x | documentation build and navigation |
| Rust / cargo | current stable; setup-only when installing the pinned mdBook CLI | environment provisioning |
| GCC | major 12 through 16; CI pins official-image `12.5.0` as the release baseline and `16.1.0` as the newest-supported lane | HACL\* build and ASan/UBSan harness |
| OpenSSL | 3.x | TLS and Ed25519 interop |
| curl | 8.x | independent HTTPS client interop |
| Python | 3.10 through 3.14 | gate tooling and record interop |
| Python `cryptography` | `>=46.0.0,<48`, declared in `requirements-gate.txt` | independent record-layer open/tamper checks |

The canonical registry id and exact commands are in `scripts/gate-registry.json`. `full-release` runs all
native/live checks; `pr` omits the expensive live interop and sanitizer checks but retains environment,
proof, parser, placeholder, provenance, and binding-contract checks.

## Setup

Install the Lean version pinned by the repository, a supported GCC/OpenSSL/curl/Python toolchain, then install
the declared Python dependency in an isolated environment:

```sh
python3 -m venv .git-exclude/venv-gate
. .git-exclude/venv-gate/bin/activate
python3 -m pip install -r requirements-gate.txt
cargo install mdbook --version 0.5.4 --locked
bash scripts/check-gate-environment.sh --profile full-release
bash scripts/gate.sh --profile full-release
```

Set `TMPDIR` to any writable private directory if the host's `/tmp` is unavailable. `gate.sh` otherwise uses
`.git-exclude/tmp` and exports it to child gates. Gate outputs are written to ignored `gate-out/`:

- `gate-ledger.json` — candidate revision, registry id, environment, commands, statuses, timings, and hashes;
- `GATE-RUN.md` — human-readable candidate summary;
- `logs/` — stdout/stderr retained by CI as an artifact.

Neither a historical ledger nor a successful subset attests a new candidate. AR0 requires a clean-tree,
exact-revision, 100%-passing `full-release` ledger.

## Registry changes

Adding, removing, renaming, or reordering a canonical gate is a versioned policy change:

1. change the one gate-table constructor in `scripts/gate.sh`;
2. update both profile lists in `scripts/gate-registry.json` and bump `gate_registry`;
3. run `scripts/check-gate-registry.sh --selftest` and `scripts/check-release-machinery.sh`;
4. update the sidecar/release documentation when the evidence contract changes.

The registry checker compares emitted ids and order exactly. Its negative controls prove that a missing gate
id and a stale registry version fail before the expensive gate body runs.
