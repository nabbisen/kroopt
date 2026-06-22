import Kroopt.Crypto.Provider
import Kroopt.Crypto.CertLint

/-!
# Kroopt.Crypto

The crypto trusted boundary (RFC 008, RFC 009): the provider capability model and
interface, plus the deterministic fake provider. The verified core never imports
this zone — it emits `CryptoOp` actions and the interpreter submits them here.
-/
