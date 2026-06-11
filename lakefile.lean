import Lake
open Lake DSL

/-!
kroopt — a Lean 4 TLS secure-channel library.

This lakefile builds the **M0 pure verified core** (RFC 001, 002, 024): the
state/event/action model, the `step` function, and the structural proofs. It
has no native crypto and no iotakt dependency, matching the `core` build
profile of RFC 024 §4 — `lake build` works on a clean Lean environment with no
C compiler and no OS reactor.

Later milestones add separate libraries behind explicit targets:
  * `Kroopt.Crypto.*` — provider interface + HACL*/EverCrypt FFI wrappers (M6).
  * `Kroopt.Conn.*`   — iotakt interpreter (M7), requires the iotakt dependency.
  * `native/*`        — C shim (M6), requires a C toolchain.
The verified core never imports those layers (RFC 001 §9, RFC 022 §3).
-/

package kroopt where
  -- Match the iotakt/henret sibling convention: no auto-bound implicits in the
  -- verified core, so every binder is explicit and reviewable.
  leanOptions := #[⟨`autoImplicit, false⟩]

/-- The pure verified core (RFC 001 Lean-only core). Builds standalone: no
native code, no FFI, no iotakt import. This is the only default target at M0. -/
@[default_target]
lean_lib Kroopt where
  globs := #[.one `Kroopt,
             .andSubmodules `Kroopt.Core,
             .andSubmodules `Kroopt.Parse,
             .andSubmodules `Kroopt.Proofs]

/-- Deterministic, Lean-only model test: drives `Kroopt.Core.step` directly
with scripted input events and asserts the resulting state/action behaviour
(RFC 014 §5). No sockets, no real time, no real crypto. -/
@[default_target]
lean_exe «kroopt-model-test» where
  root := `Tests.Model

/-- Deterministic parser unit + negative tests (RFC 003 §11). -/
@[default_target]
lean_exe «kroopt-parse-test» where
  root := `Tests.Parse

/-- Bounded smoke fuzzer for the parser primitives (RFC 003 §11, RFC 023). -/
@[default_target]
lean_exe «kroopt-parse-fuzz» where
  root := `Tests.Fuzz
