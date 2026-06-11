import Kroopt.Core.Crypto
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
open Kroopt.Core (SecretKeyHandle)

/-- A bounded, generation-tagged store mapping handle ids to secret bytes.
Pure value: threaded explicitly through the provider and interpreter rather than
hidden in an `IORef`, so the crypto seam stays deterministic and testable. -/
structure SecretArena where
  entries    : List (UInt64 × ByteArray)
  released   : List UInt64
  nextId     : UInt64
  generation : UInt64
  capacity   : Nat
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
  { a with entries := [], released := [], generation := a.generation + 1, nextId := 1 }

end SecretArena
end Kroopt.Crypto
