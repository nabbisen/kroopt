import Kroopt.Core.State

/-!
# Kroopt.Core.Budget

The resource-budget model and its enforcement primitives (RFC 019). Every buffer
kroopt owns and every loop it runs has a configured ceiling; charging against a
ceiling is a pure, total, deterministic operation that either returns the updated
counter or a typed `ResourceLimitError`. Exceeding a limit is a **security
failure**, not routine backpressure — an attacker must not be able to force
unbounded allocation or unbounded work with fragmented or oversized input.

The DoS-relevant guarantee proved in `Kroopt.Proofs.Budget` is that an *accepted*
charge never leaves a counter above its ceiling: the budget is a hard bound, not
a hint.
-/

namespace Kroopt.Core

open Kroopt (ResourceLimitError)

/-- Charge `n` handshake bytes against the total handshake budget (RFC 019). -/
def chargeHandshakeBytes (lim : ResourceLimits) (b : BudgetState) (n : Nat) :
    Except ResourceLimitError BudgetState :=
  let total := b.handshakeBytesSeen + n
  if total > lim.maxHandshakeBytes then .error .handshakeBytes
  else .ok { b with handshakeBytesSeen := total }

/-- Charge `n` ClientHello bytes against the ClientHello budget. -/
def chargeClientHelloBytes (lim : ResourceLimits) (b : BudgetState) (n : Nat) :
    Except ResourceLimitError BudgetState :=
  let total := b.clientHelloBytesSeen + n
  if total > lim.maxClientHelloBytes then .error .clientHelloBytes
  else .ok { b with clientHelloBytesSeen := total }

end Kroopt.Core
