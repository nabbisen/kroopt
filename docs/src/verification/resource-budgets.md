# Resource budgets and DoS defense

At the edge, every kroopt-owned buffer and every loop it runs has a configured
ceiling (RFC 019). `ResourceLimits` holds the ceilings; `BudgetState` holds the
per-connection counters. Charging against a ceiling is a pure, total,
deterministic operation returning either the updated counter or a typed
`ResourceLimitError`. Exceeding a limit is a **security failure**, not routine
backpressure — it terminates the connection and never yields partial plaintext.

The DoS-relevant property is proved, not asserted: an *accepted* charge never
leaves a counter above its ceiling (`chargeHandshakeBytes_bounded`,
`chargeExtensions_bounded`, `chargeProgressStep_bounded`), and an over-limit
charge is rejected deterministically (`chargeHandshakeBytes_rejects_over`,
`checkRecordSize_rejects_over`). So an attacker cannot drive a counter past its
bound with fragmented or oversized input.

Enforcement points: the parser already bounds the ClientHello size, the extension
count, and every length-prefixed vector by construction (RFC 003); the record
framer bounds record size; the interpreter's progress loop is fuel-bounded so it
can never spin on repeated `wouldBlock`; and the budget primitives above provide
the total-handshake-byte, pending-ciphertext, and progress-step ceilings. A
budget failure routes through the same fatal path as any other protocol error,
which is proved to emit no plaintext.
