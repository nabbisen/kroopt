import Kroopt.Error
import Kroopt.Core.Step

/-!
# kroopt

A Lean 4 TLS secure-channel library: a pure verified protocol core driven by a
thin imperative interpreter, positioned between `iotakt` (byte transport) and
`jemmet` (HTTP). This root module re-exports the M0 verified core.

The public connection API (`Kroopt.Conn.*`), crypto provider, and native shim
are added in later milestones and are not part of the M0 surface.
-/
