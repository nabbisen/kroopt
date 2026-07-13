# RFC 048 — Validated Construction and Protected-Epoch Fail-Closed Behavior

**Project.** kroopt  
**Status.** Proposed  
**Type.** Blocking construction/interpreter security fix  
**Target milestone.** AR1  
**Requires completion of.** [RFC 008](../done/008-crypto-provider-capability-and-ffi-contract.md), [RFC 010](../done/010-tlsconn-api-nonblocking-interpreter.md), [RFC 031](../done/031-production-interpreter-correspondence.md), [RFC 034](../done/034-provider-capability-honesty-and-entropy.md)  
**Touches.** config/capability validation, `TlsConn.serverWith`, interpreter flight framing, tests  

## Review finding

Architecture review B4 found two related bypasses: a missing handshake write key can fall back to a plaintext
handshake record at a protected epoch, and public connection construction does not require config/provider
capability validation before creating a connection.

## Decision

There is one production-capable construction boundary. Validation returns an opaque `ValidatedRuntime`
token after checking configuration, provider capabilities, certificate/key compatibility, limits, and
initial secret provisioning. `TlsConn.server` accepts only that token; it cannot accept raw config or a raw
provider pair.

`ValidatedRuntime` has a private representation and no public field projections, structure literal, record
update, or unchecked constructor. Its invariant binds the exact config generation, provider identity and
capability digest, certificate/key binding, limits, and provisioning generation. Replacing or mutating any
bound component requires revalidation and produces a new token. Test helpers may validate fake providers,
but cannot forge or unwrap a production token.

At `handshake` or `application` epoch, absence or mismatch of the required key/suite is an internal invariant
failure and terminal. Only the initial epoch may frame plaintext handshake/alert records where TLS permits.

## Work breakdown

1. Introduce a validated listener/runtime bundle tying config generation to provider capabilities.
2. Define `ValidatedRuntime` as an opaque public type backed by a private structure in the validation module;
   export only safe query operations and the validated connection constructor.
3. Make validation return `Except ConfigError ValidatedRuntime`; make `TlsConn.server` consume/borrow only
   that token and remove raw `TlsConn` structure construction from the public API.
4. Remove public setters/record updates for provider, config, capabilities, and generation. Reload/provider
   replacement must call validation and atomically publish a new token.
5. Remove default baseline config from production construction and isolate fake-provider conveniences in
   explicit test modules that still pass through invariant validation.
6. Replace protected-flight plaintext fallback with a terminal fail-closed path.
7. Validate crypto results for required installed-key postconditions, not only result variant.
8. Add compile-fail/API-surface checks for structure literals, record updates, raw provider replacement, and
   generation mismatch, plus runtime missing/wrong-key negative tests.

## Acceptance criteria

1. No public API can construct or mutate a production connection/runtime from an unvalidated config/provider
   pair; direct structure literals and record updates are impossible outside the defining module.
2. Protected-epoch missing/wrong keys emit no plaintext handshake or alert record.
3. Capability mismatch fails before any connection state or transport action exists.
4. Tests cover fake, real, and deliberately malformed providers through every constructor path.
5. Correspondence tests show the interpreter adds no protocol decision.
6. External API docs and examples use only the validated construction path.
7. Config reload and provider replacement invalidate the old binding and require a newly validated token;
   generation/provider mismatch cannot be represented through the public API.

## Non-goals

This RFC does not implement native traffic-secret residency
([RFC 040](040-native-traffic-secret-arena.md)) or asynchronous providers
([RFC 044](044-async-crypto-offload-and-result-correlation.md)).
