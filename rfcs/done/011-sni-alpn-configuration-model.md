# RFC 011 — SNI/ALPN Configuration Model

**Project.** kroopt  
**Status.** Implemented (0.24.0-dev)  
**Type.** Implementation RFC  
**Target milestone.** M8  
**Depends on.** RFC 010  
**Touches.** `Kroopt/Conn/Config.lean`  
**Canonical source.** kroopt fixed requirements and external design.  

---

## 1. Summary

This RFC defines kroopt's immutable server configuration model for SNI certificate selection and ALPN negotiation. The initial release line uses a validated configuration table, not callbacks, to avoid blocking, reentrancy, nondeterminism, and proof/test complexity.

## 2. Goals

- Define immutable validated `ServerConfig`.
- Define SNI matching rules.
- Define ALPN selection rules.
- Define config generation and reload semantics.
- Keep ALPN policy ownership with jemmet.

## 3. Public configuration API sketch

```lean
structure ServerConfig where
  generation : ConfigGeneration
  defaultEndpoint : EndpointConfig
  sniTable : List SniRoute
  globalPolicy : TlsPolicy
  budgets : TlsBudgets

structure SniRoute where
  pattern : ServerNamePattern
  endpoint : EndpointConfig

structure EndpointConfig where
  certChain : CertificateChainHandle
  privateKey : PrivateKeyHandle
  allowedAlpn : List ALPNProtocol
  signatureSchemes : List SignatureScheme
  cipherSuites : List CipherSuite
```

Constructors validate the config and return either a `ServerConfig` or a list of configuration errors/warnings.

## 4. SNI rules

- SNI input is parsed and normalized according to a strict documented rule.
- Empty or absent SNI uses `defaultEndpoint` if configured.
- Exact-name matches are preferred over wildcard matches.
- Wildcard matching, if enabled, is limited to a single leftmost label.
- Invalid SNI values are rejected or ignored according to TLS policy; raw invalid names are not logged.
- SNI selection must be deterministic.

## 5. ALPN rules

- jemmet supplies the offer list or configured list per listener.
- kroopt selects a protocol from the intersection of client ALPN and endpoint allowed ALPN according to configured priority.
- If no ALPN is selected, behavior is policy-controlled: either continue with `none` or fail handshake.
- kroopt reports the selected ALPN; jemmet chooses the protocol handler.

## 6. Config generation and reload

Config reload creates a new validated config object with a new generation. Existing connections keep their config generation. New connections use the new config. In-flight handshakes do not see mid-handshake mutation.

This prevents a class of bugs where certificate selection, transcript construction, and CertificateVerify signing observe inconsistent configuration.

## 7. Internal design

```lean
def validateServerConfig : RawServerConfig -> IO (Except ConfigError ServerConfig)
def selectEndpoint : ServerConfig -> Option ServerName -> Except TlsError SelectedEndpoint
def negotiateAlpn : SelectedEndpoint -> Option (List ALPNProtocol) -> Except TlsError (Option ALPNProtocol)
```

Validation includes certificate/key compatibility hooks from RFC 012 and provider capability checks from RFC 008.

## 8. Security considerations

- Do not call user callbacks during ClientHello processing in the initial release line.
- Do not log full attacker-controlled SNI values without redaction.
- Do not permit config reload to mutate live endpoint objects.
- Do not select a certificate before SNI parse validation.
- Do not allow ALPN negotiation to select a protocol not offered by jemmet/config.

## 9. Tests

- Exact SNI match.
- Wildcard match if enabled.
- Default endpoint fallback.
- Invalid SNI handling.
- ALPN intersection priority.
- ALPN no-overlap behavior.
- Config reload generation isolation.
- Certificate/key compatibility validation integration.

## 10. Acceptance criteria

- `ServerConfig` is immutable after validation.
- SNI and ALPN behavior are deterministic and documented.
- Config generation is carried into connection state.
- No callback-based SNI policy is required in the initial release line.
