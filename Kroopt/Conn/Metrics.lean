import Kroopt.Error

/-!
# Operational metrics and error categories (RFC 015 §6, §8; RFC 020 §10.2/§10.3)

Non-secret, bounded operational counters and the coarse public error-category enum. These live in a
low module so the live driver (`Conn.Interpreter`) can update the counters during a real handshake,
while the consumer-facing redacted error view (`Conn.Uniform`) reuses the same category type. The
counters are an **internal** capability: there is no public accessor and no export format here — live
emission/histograms/aggregation/export are RFC 020 v0.4 work.
-/

namespace Kroopt.Conn

open Kroopt (TlsError)

/-- The coarse error category exposed to the consumer for logging. Intentionally coarse and stable
(RFC 020 §10.3); finer causes remain internal detail. -/
inductive ErrorCategory where
  | protocol | parse | crypto | config | resource | transport | closed | internal
  deriving DecidableEq, Repr, Inhabited

def categoryOf : TlsError → ErrorCategory
  | .protocol _              => .protocol
  | .parse _                 => .parse
  | .crypto _                => .crypto
  | .config _                => .config
  | .resourceLimit _         => .resource
  | .transport _             => .transport
  | .closed                  => .closed
  | .internalInvariantFailure => .internal

/-- Non-secret, bounded counters for operational visibility (RFC 015 §8). No field can hold a secret,
plaintext, or attacker-controlled value — these are counts only. -/
structure Metrics where
  handshakesCompleted : Nat := 0
  handshakesFailed    : Nat := 0
  alertsClassified    : Nat := 0  -- fatal alerts the core classified for a failure (see RFC: not
                                   -- necessarily transmitted; the interpreter terminates on `failWithAlert`)
  alertsSent          : Nat := 0  -- fatal alert *records* actually framed onto the wire (RFC 041). Best-
                                  -- effort delivery means this can be ≤ `alertsClassified` (a protected-epoch
                                  -- alert is classified but, until the seal path lands, not yet sent)
  resourceFailures    : Nat := 0
  alpnSelected        : Nat := 0
  deriving Repr, Inhabited, DecidableEq

namespace Metrics

def recordHandshakeComplete (m : Metrics) (alpnNegotiated : Bool) : Metrics :=
  { m with handshakesCompleted := m.handshakesCompleted + 1
           alpnSelected := m.alpnSelected + (if alpnNegotiated then 1 else 0) }

def recordFailure (m : Metrics) (cat : ErrorCategory) : Metrics :=
  { m with handshakesFailed := m.handshakesFailed + 1
           resourceFailures := m.resourceFailures + (if cat == .resource then 1 else 0) }

def recordAlertClassified (m : Metrics) : Metrics := { m with alertsClassified := m.alertsClassified + 1 }

def recordAlertSent (m : Metrics) : Metrics := { m with alertsSent := m.alertsSent + 1 }

end Metrics

end Kroopt.Conn
