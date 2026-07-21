import Kroopt.Error
import Kroopt.Core.Step

/-!
# kroopt

A Lean 4 TLS secure-channel library: a pure verified protocol core driven by a
thin imperative interpreter, positioned between `iotakt` (byte transport) and
`jemmet` (HTTP). This root module intentionally re-exports the verified core.

The public connection API (`Kroopt.Conn.*`), crypto provider, and native shim are
available through their explicit modules rather than this small root surface.
-/
