# Resource budgets and DoS defense

At the edge, every kroopt-owned buffer and every loop it runs has a configured
ceiling (RFC 019). `ResourceLimits` holds the ceilings; they are part of the
listener's validated configuration and travel with the connection
(`State.serverConfig.limits`, RFC 042 B1), so a deployment can tune them and
jemmet can derive them from its own budget. `BudgetState` holds the two
per-connection byte counters that are charged on the inbound handshake path.

The DoS-relevant property is proved where a charge exists: an *accepted*
handshake-byte charge never leaves the counter above its ceiling
(`chargeHandshakeBytes_bounded`), an over-limit charge is rejected
deterministically (`chargeHandshakeBytes_rejects_over`), and an accepted charge
accounts for exactly the bytes charged (`chargeHandshakeBytes_accounts`). The
other ceilings are enforced by the mechanism that actually runs rather than by a
budget charge, and are tested/documented there (RFC 042 C2):

- **inbound record size** — the parser rejects an over-length record
  (`Parse.Reader.lengthExceedsMax → .oversizedRecord`), surfaced on the record
  path as a fatal `recordFailAlert`;
- **extension count** — bounded transitively by `maxClientHelloBytes` (extensions
  live inside the byte-bounded ClientHello) and the proven parser bounds-safety;
- **progress-loop steps** — bounded structurally by `driveEvents` fuel recursion,
  whose fuel is the connection's `maxProgressStepsPerCall`; the loop terminates in
  at most that many steps by construction, so it can never spin on repeated
  `wouldBlock`;
- **outbound ciphertext** — bounded by the interpreter egress backstop. Before
  accepting more plaintext for encryption, `TlsConn.send` admits only a prefix
  whose sealed record keeps the kroopt-owned outbound queue within
  `maxPendingCiphertextBytes`; the hard invariant `rt.outbound.size ≤ cap` holds
  after any successful send (RFC 042 A1). `TlsConn.ownedOutboundBytes` exposes the
  same queue size to consumers. This is interpreter buffer/back-pressure
  management beside `rt.outbound`, not a verified-core property — so it is covered
  by the egress tests in `Tests/Conn`, not by a `Core.step` proof. Fatal alert
  records are terminal-control records: they are queued best-effort even when the
  app cap is full (one record, then terminalization), so they bypass the backstop
  by design.

A budget or parser failure routes through the same fatal path as any other
protocol error, which is proved to emit no plaintext.
