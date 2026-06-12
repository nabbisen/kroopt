import Kroopt.Core.Crypto
import Kroopt.Core.Record
import Kroopt.Error

/-!
# Kroopt.Crypto.SecretArena

The stateful secret store that backs `SecretKeyHandle` (RFC 008 §6, RFC 013 §13,
RFC 018 §3.5). This is the piece the *pure, stateless* `CryptoProvider.submit`
could not provide on its own: real ECDHE/HKDF outputs are secret *bytes* that
later operations (the key schedule, AEAD) must read back, and a pure function
cannot carry that state between calls. The arena makes the crypto seam stateful
while keeping **handle opacity** — the verified core still only ever sees
`SecretKeyHandle`s, never key bytes, so its proofs are untouched.

Design notes:

* Handles carry the arena `generation`. A handle minted under an old generation
  is rejected by `get` after `bumpGeneration` (connection reset / config
  reload), giving the same stale-reference rejection discipline the core proves
  for crypto *results* (RFC 008 §5).
* The store is bounded by `capacity` (RFC 019): allocation past the bound is a
  typed failure, never unbounded growth.
* Zeroization is best-effort and lives in the C secret arena (RFC 013 §13.4);
  on the Lean side `release`/`bumpGeneration` drop the references. Documented
  honestly, not proven.

This module lives in the trusted `Crypto` zone and imports only `Core` types; it
is never imported by the pure verified core (enforced by the dependency gate).
-/

namespace Kroopt.Crypto

open Kroopt (CryptoError)
open Kroopt.Core (SecretKeyHandle Direction Epoch)

/-- A bounded, generation-tagged store mapping handle ids to secret bytes.
Pure value: threaded explicitly through the provider and interpreter rather than
hidden in an `IORef`, so the crypto seam stays deterministic and testable. -/
structure SecretArena where
  entries    : List (UInt64 × ByteArray)
  released   : List UInt64
  nextId     : UInt64
  generation : UInt64
  capacity   : Nat
  /-- Installed record keys, keyed by (direction, epoch): the ids of the key and
  IV entries. Lets `aeadSeal`/`aeadOpen` (keyed by record metadata) resolve the
  installed key without the verified core ever naming key bytes. -/
  installed  : List (Direction × Epoch × UInt64 × UInt64) := []
  /-- Base traffic-secret id per epoch, recorded at key install, so the Finished
  key (HKDF-Expand-Label of the base secret) can be derived on demand. -/
  baseSecrets : List (Epoch × UInt64) := []
  deriving Inhabited

namespace SecretArena

/-- An empty arena at a given generation with a capacity bound. Ids start at 1 so
that `⟨0, _⟩` can never be a live allocation. -/
def withCapacity (cap : Nat) (gen : UInt64 := 0) : SecretArena :=
  { entries := [], released := [], nextId := 1, generation := gen, capacity := cap }

/-- Default arena (capacity 64 — far above the handful of secrets a single
TLS 1.3 handshake needs). -/
def empty : SecretArena := withCapacity 64

/-- Number of live (un-released) secrets. -/
def liveCount (a : SecretArena) : Nat := a.entries.length

/-- Store secret bytes and return an opaque handle. Fails (typed) at the capacity
bound rather than growing without limit (RFC 019). -/
def store (a : SecretArena) (bytes : ByteArray) :
    Except CryptoError (SecretKeyHandle × SecretArena) :=
  if a.entries.length ≥ a.capacity then
    .error .providerInternal
  else
    let id := a.nextId
    let h : SecretKeyHandle := ⟨id, a.generation⟩
    .ok (h, { a with entries := (id, bytes) :: a.entries, nextId := id + 1 })

/-- Read the bytes a handle names. `none` if the handle's generation does not
match (stale handle) or the entry was released — never the wrong secret. -/
def get (a : SecretArena) (h : SecretKeyHandle) : Option ByteArray :=
  if h.generation == a.generation then
    (a.entries.find? (fun e => e.1 == h.id)).map (fun e => e.2)
  else none

/-- Whether a handle's id has been released. -/
def isReleased (a : SecretArena) (h : SecretKeyHandle) : Bool := a.released.contains h.id

/-- Release a secret: drop the entry and record the id. Idempotent. -/
def release (a : SecretArena) (h : SecretKeyHandle) : SecretArena :=
  { a with entries := a.entries.filter (fun e => e.1 != h.id),
           released := h.id :: a.released }

/-- Bump the generation, invalidating every outstanding handle at once
(connection reset / config reload). Previous entries are dropped. -/
def bumpGeneration (a : SecretArena) : SecretArena :=
  { a with entries := [], released := [], installed := [], baseSecrets := [],
           generation := a.generation + 1, nextId := 1 }

/-- Record an installed record key and IV for a (direction, epoch). -/
def recordInstalled (a : SecretArena) (dir : Direction) (epoch : Epoch)
    (keyId ivId : UInt64) : SecretArena :=
  { a with installed := (dir, epoch, keyId, ivId) :: a.installed }

/-- Look up the installed key/IV entry ids for a (direction, epoch). -/
def lookupInstalled (a : SecretArena) (dir : Direction) (epoch : Epoch) :
    Option (UInt64 × UInt64) :=
  (a.installed.find? (fun e => decide (e.1 = dir) && decide (e.2.1 = epoch))).map
    (fun e => (e.2.2.1, e.2.2.2))

/-- Record the base traffic-secret entry id for an epoch (for the Finished key). -/
def recordBaseSecret (a : SecretArena) (epoch : Epoch) (secretId : UInt64) : SecretArena :=
  { a with baseSecrets := (epoch, secretId) :: a.baseSecrets }

/-- Look up the base traffic-secret entry id for an epoch. -/
def lookupBaseSecret (a : SecretArena) (epoch : Epoch) : Option UInt64 :=
  (a.baseSecrets.find? (fun e => decide (e.1 = epoch))).map (fun e => e.2)

/-- Read bytes by raw entry id at the current generation. -/
def getById (a : SecretArena) (id : UInt64) : Option ByteArray :=
  (a.entries.find? (fun e => e.1 == id)).map (fun e => e.2)

end SecretArena
end Kroopt.Crypto
