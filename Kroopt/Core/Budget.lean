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

/-- Configured per-connection ceilings (RFC 019 §7, external design §5.5). The
defaults are conservative and TLS 1.3-appropriate (record plaintext capped at
2^14 by the spec). -/
structure ResourceLimits where
  maxHandshakeBytes         : Nat := 65536
  maxClientHelloBytes       : Nat := 16384
  maxExtensions             : Nat := 64
  maxRecordPlaintextBytes   : Nat := 16384       -- 2^14, RFC 8446 §5.1
  maxPendingCiphertextBytes : Nat := 1048576
  maxPendingCryptoOps       : Nat := 16
  maxProgressStepsPerCall   : Nat := 256
  deriving Repr, Inhabited

def ResourceLimits.standard : ResourceLimits := {}

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

/-- Charge `k` extensions against the extension-count budget. -/
def chargeExtensions (lim : ResourceLimits) (b : BudgetState) (k : Nat) :
    Except ResourceLimitError BudgetState :=
  let total := b.extensionsSeen + k
  if total > lim.maxExtensions then .error .extensionCount
  else .ok { b with extensionsSeen := total }

/-- Account for one progress-loop step; exceeding the per-call budget is fatal so
the event loop can never spin (RFC 010 §10, RFC 019). -/
def chargeProgressStep (lim : ResourceLimits) (b : BudgetState) :
    Except ResourceLimitError BudgetState :=
  let total := b.progressStepsThisCall + 1
  if total > lim.maxProgressStepsPerCall then .error .progressSteps
  else .ok { b with progressStepsThisCall := total }

/-- A record-plaintext size check (no counter; a per-record bound). Exceeding the
TLS 1.3 maximum is fatal before any allocation (RFC 019). -/
def checkRecordSize (lim : ResourceLimits) (n : Nat) : Except ResourceLimitError Unit :=
  if n > lim.maxRecordPlaintextBytes then .error .recordSize else .ok ()

/-- Charge pending ciphertext bytes against the outbound-queue budget. -/
def chargePendingCiphertext (lim : ResourceLimits) (b : BudgetState) (n : Nat) :
    Except ResourceLimitError BudgetState :=
  let total := b.pendingCiphertextBytes + n
  if total > lim.maxPendingCiphertextBytes then .error .pendingCiphertext
  else .ok { b with pendingCiphertextBytes := total }

end Kroopt.Core
