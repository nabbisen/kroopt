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

/-- Shared test vectors (published KATs with explicit provenance), imported by
test executables so vector definitions live in one audited place. -/
lean_lib «KrooptTestVectors» where
  globs := #[.one `Tests.Vectors.Ed25519Rfc8032]

/-- Shared real-handshake fixtures (x25519 share, Ed25519 cert, ClientHello, `RealCryptoConfig`)
imported by the correspondence tests, so they live in exactly one place (RFC 031 §5). -/
lean_lib «KrooptTestSupport» where
  globs := #[.one `Tests.RealFixtures]

/-- Deterministic, Lean-only model test: drives `Kroopt.Core.step` directly
with scripted input events and asserts the resulting state/action behaviour
(RFC 014 §5). No sockets, no real time, no real crypto. -/
@[default_target]
lean_exe «kroopt-model-test» where
  root := `Tests.Model
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Deterministic parser unit + negative tests (RFC 003 §11). -/
@[default_target]
lean_exe «kroopt-parse-test» where
  root := `Tests.Parse
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Unit and negative tests for the TLS 1.3 record model (RFC 004 §13). -/
@[default_target]
lean_exe «kroopt-record-test» where
  root := `Tests.Record
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Unit and negative tests for sequence/nonce/key-separation (RFC 005 §10). -/
@[default_target]
lean_exe «kroopt-nonce-test» where
  root := `Tests.Nonce
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Synthetic handshake trace + transcript tests (RFC 006 §12, RFC 007 §10). -/
@[default_target]
lean_exe «kroopt-handshake-test» where
  root := `Tests.Handshake
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Full handshake end-to-end through `step` with fake crypto/transport (RFC 014). -/
@[default_target]
lean_exe «kroopt-e2e-test» where
  root := `Tests.EndToEnd
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Crypto provider capability + operation-id correlation tests (RFC 008). -/
@[default_target]
lean_exe «kroopt-crypto-test» where
  root := `Tests.Crypto
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- TlsConn API + non-blocking interpreter tests (RFC 010). -/
@[default_target]
lean_exe «kroopt-conn-test» where
  root := `Tests.Conn
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- SNI/ALPN configuration + certificate-presentation tests (RFC 011, 012). -/
@[default_target]
lean_exe «kroopt-config-test» where
  root := `Tests.Config
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Alerts, close_notify, and terminal-policy tests (RFC 013). -/
@[default_target]
lean_exe «kroopt-close-test» where
  root := `Tests.Close
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- No-secrets trace facility tests (RFC 036 §3). -/
lean_exe «kroopt-trace-test» where
  root := `Tests.Trace
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Captured-client ClientHello replay bridge (RFC 036 §2). -/
lean_exe «kroopt-replay-test» where
  root := `Tests.Replay
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- jemmet integration + end-to-end HTTPS acceptance tests (RFC 015). -/
@[default_target]
lean_exe «kroopt-https-test» where
  root := `Tests.E2EHttps
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Resource-budget + deferred-feature scope-control tests (RFC 019, 016). -/
@[default_target]
lean_exe «kroopt-hardening-test» where
  root := `Tests.Hardening
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- Bounded smoke fuzzer for the parser primitives (RFC 003 §11, RFC 023). -/
@[default_target]
lean_exe «kroopt-parse-fuzz» where
  root := `Tests.Fuzz
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- v0.3 native crypto: compile the vendored HACL* portable-C subset and the
Lean FFI glue into a static library linked into the FFI-using executables.
Requires a C toolchain (gcc/clang). The pure verified core never depends on this;
only the real `Hacl` provider path and its KAT test do. -/
extern_lib krooptCrypto (pkg : NPackage _package.name) := do
  let nativeDir := pkg.dir / "Kroopt" / "Native"
  let haclDir   := nativeDir / "hacl"
  let leanInc   ← getLeanIncludeDir
  let cFlags := #[
    "-I" ++ haclDir.toString, "-I" ++ (haclDir / "internal").toString,
    "-I" ++ (haclDir / "include").toString, "-I" ++ (haclDir / "minimal").toString,
    "-I" ++ nativeDir.toString, "-I" ++ leanInc.toString,
    "-std=c11", "-O2", "-fPIC", "-fwrapv", "-D_GNU_SOURCE", "-w",
    "-ffunction-sections", "-fdata-sections"]
  let cFiles : Array (String × String) := #[
    ("hacl/Hacl_Curve25519_51.c",      "Hacl_Curve25519_51.o"),
    ("hacl/Hacl_Chacha20Poly1305_32.c","Hacl_Chacha20Poly1305_32.o"),
    ("hacl/Hacl_Chacha20.c",           "Hacl_Chacha20.o"),
    ("hacl/Hacl_Poly1305_32.c",        "Hacl_Poly1305_32.o"),
    ("hacl/Hacl_Hash_SHA2.c",          "Hacl_Hash_SHA2.o"),
    ("hacl/Hacl_Streaming_SHA2.c",     "Hacl_Streaming_SHA2.o"),
    ("hacl/Hacl_HKDF.c",               "Hacl_HKDF.o"),
    ("hacl/Hacl_HMAC.c",               "Hacl_HMAC.o"),
    ("hacl/Hacl_Ed25519.c",            "Hacl_Ed25519.o"),
    ("hacl/Hacl_P256.c",               "Hacl_P256.o"),
    ("hacl/Hacl_Bignum256.c",          "Hacl_Bignum256.o"),
    ("hacl/Hacl_Bignum.c",             "Hacl_Bignum.o"),
    ("hacl/Hacl_RSAPSS.c",             "Hacl_RSAPSS.o"),
    ("hacl/Lib_Memzero0.c",            "Lib_Memzero0.o"),
    ("kroopt_ffi.c",                   "kroopt_ffi.o"),
    ("kroopt_socket.c",                "kroopt_socket.o")]
  -- AES-GCM via HACL*/EverCrypt's Vale verified x86_64 assembly (RFC 008/009). HACL_CAN_COMPILE_VALE
  -- gates both the CPUID detection in EverCrypt_AutoConfig2_init AND the create_in AES path; the
  -- VEC128/256 macros + ISA flags let libintvector.h declare the vector types the AEAD headers use.
  -- The .S files (no #include) harmlessly ignore the C-only flags in this shared set.
  let aesFlags := cFlags ++ #[
    "-DHACL_CAN_COMPILE_VALE=1", "-DHACL_CAN_COMPILE_VEC128", "-DHACL_CAN_COMPILE_VEC256",
    "-mavx2", "-mavx", "-maes", "-mpclmul", "-msse4.2"]
  let aesFiles : Array (String × String) := #[
    ("hacl/EverCrypt_AEAD.c",          "EverCrypt_AEAD.o"),
    ("hacl/EverCrypt_AutoConfig2.c",   "EverCrypt_AutoConfig2.o"),
    ("hacl/aesgcm-x86_64-linux.S",     "aesgcm_x86_64.o"),
    ("hacl/cpuid-x86_64-linux.S",      "cpuid_x86_64.o"),
    ("kroopt_aesgcm.c",                "kroopt_aesgcm.o")]
  let oJobs ← cFiles.mapM fun (cFile, oFile) => do
    let src    := nativeDir / cFile
    let obj    := pkg.buildDir / "c" / oFile
    let srcJob ← inputFile src false
    buildO obj srcJob cFlags
  let aesJobs ← aesFiles.mapM fun (cFile, oFile) => do
    let src    := nativeDir / cFile
    let obj    := pkg.buildDir / "c" / oFile
    let srcJob ← inputFile src false
    buildO obj srcJob aesFlags
  buildStaticLib (pkg.buildDir / "lib" / "libkroopt_crypto.a") (oJobs ++ aesJobs)

/-- Native HACL* crypto known-answer tests (v0.3 binding). Links `krooptCrypto`.
`--gc-sections` drops the agile-HMAC hash variants (SHA-1/Blake2) the suite never
calls, which would otherwise be undefined at link. -/
@[default_target]
lean_exe «kroopt-hacl-test» where
  root := `Tests.Hacl
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-nativesecret-test» where
  root := `Tests.NativeSecret
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- M13 provider-arena refactor: the real TLS 1.3 key schedule validated against
RFC 8448 §3, plus the secret arena driving a real key into the AEAD. Links the
HACL* FFI lib. -/
@[default_target]
lean_exe «kroopt-keyschedule-test» where
  root := `Tests.KeySchedule
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- M14 enriched crypto interface: the real HACL-backed `CryptoProvider` driven
through the RFC 8448 §3 handshake op sequence via `submit`. Links the FFI lib. -/
@[default_target]
lean_exe «kroopt-realprovider-test» where
  root := `Tests.RealProvider
  moreLinkArgs := #["-Wl,--gc-sections"]

/-- M15 verified key-schedule orchestrator driving the real provider through the
RFC 8448 §3 handshake. Links the FFI lib. -/
@[default_target]
lean_exe «kroopt-scheduledriver-test» where
  root := `Tests.ScheduleDriver
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-provision-test» where
  root := `Tests.Provision
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-wire-test» where
  root := `Tests.Wire
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-flight-test» where
  root := `Tests.Flight
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-correspondence-test» where
  root := `Tests.Correspondence
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-record13-test» where
  root := `Tests.Record13
  moreLinkArgs := #["-Wl,--gc-sections"]

@[default_target]
lean_exe «kroopt-wire-dump» where
  root := `Tests.WireDump
  moreLinkArgs := #["-Wl,--gc-sections"]

@[default_target]
lean_exe «kroopt-socket-test» where
  root := `Tests.SocketHandshake
  moreLinkArgs := #["-Wl,--gc-sections"]

@[default_target]
lean_exe «kroopt-socketdriver-test» where
  root := `Tests.SocketDriver
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-live-server» where
  root := `Tests.LiveServer
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-live-server-nb» where
  root := `Tests.LiveServerNb
  moreLinkArgs := #["-Wl,--gc-sections"]

lean_exe «kroopt-realch-interop» where
  root := `Tests.RealChParse
  moreLinkArgs := #["-Wl,--gc-sections"]

@[default_target]
lean_exe «kroopt-capabilities-test» where
  root := `Tests.Capabilities
  moreLinkArgs := #["-Wl,--gc-sections"]



