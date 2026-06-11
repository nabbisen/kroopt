import Kroopt.Core.Id
import Kroopt.Core.Common
import Kroopt.Core.CipherSuite
import Kroopt.Core.Record
import Kroopt.Core.Crypto
import Kroopt.Core.Transcript
import Kroopt.Core.State
import Kroopt.Core.Event
import Kroopt.Core.Action
import Kroopt.Core.Nonce
import Kroopt.Core.RecordPath
import Kroopt.Core.Handshake
import Kroopt.Core.Step

/-!
# Kroopt.Core

The pure verified protocol core: identity and primitive types, the connection
state, input events, output actions, and the `step` transition function. No
crypto, no FFI, no iotakt (RFC 001 §9, RFC 022 §3).
-/
