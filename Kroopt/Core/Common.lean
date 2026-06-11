import Kroopt.Error

/-!
# Kroopt.Core.Common

Small shared types referenced by both `InputEvent` and `OutputAction`, factored
out to avoid an Event↔Action import cycle.
-/

namespace Kroopt.Core

open Kroopt (AlertDescription)

/-- How a connection is being closed (RFC 013 §3). `graceful` attempts an
encrypted `close_notify`; `fatal` sends a fatal alert; `abortive` closes the
transport without any TLS alert. -/
inductive CloseMode where
  | graceful
  | fatal (alert : AlertDescription)
  | abortive
  deriving DecidableEq, Repr, Inhabited

/-- Budget/timer kinds that surface as first-class protocol events (RFC 019). -/
inductive TimeoutKind where
  | handshake
  | idle
  | closeNotify
  deriving DecidableEq, Repr, Inhabited

end Kroopt.Core
