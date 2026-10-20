# Guarded NIP-46 decrypt request publication

**Unbuilt, unexecuted SDK source only.** The committed distribution and package
version are unchanged. This must be rebuilt, typechecked, tested and qualified
through the normal release/consumer gates before npm publication or KithMoot
adoption. No protected browser, external signer or device acceptance is claimed.

The existing `providerEffectBoundary === 1` gates a backend call. It explicitly
does not guard NIP-46 transport-internal frames or retries. A client must not use
that marker alone to enable remote decryption in a view whose revocation must
prevent queued request publication.

The optional `signer.nip46.decryptNip44Guarded(peer, ciphertext, boundary)` is a
separate receive-only capability. `Nip46DecryptBoundary` extends the existing
provider start/handoff contract with a synchronous `current()` check and a
mandatory `websocketImplementation`. The embedding must supply the constructor
for its selected, authorised route. There is no global/native clearnet fallback,
no inferred authentication grant and no account-signing or message-encryption
capability exposed by this method. Standard NIP-46 `nip44_decrypt` RPC events
and the existing client key/identity are retained.

Only this decrypt request's EVENT publications use the new bounded carrier.
Initial connection/login, the shared response subscription and its REQ/reconnect
frames, other methods, management and existing NIP-04/NIP-44 calls remain on their
existing path. This is not a whole-session or whole-mode network boundary.
Requests already sent to a signer cannot be retracted.

The new call snapshots its relay destinations, explicitly selected constructor
and send callable. Its own sockets check both the originating permission and
request-local lifetime immediately before construction and each synchronous send.
Each relay gets at most one identical signed RPC EVENT; there is no implicit
retry. The carrier permits at most sixteen relay entries, a 1 MiB request frame,
a bounded acknowledgement read and the configured request deadline. A matching
positive ACK closes slower owned publishers. A denied, expired, closed or settled
request cannot send on a late handshake. Explicit retry is a new caller action.

The existing response listener is registered before publication. Response,
refusal, timeout or client close removes it synchronously and thereby withdraws
publication permission. Guarded responses check permission before auth-URL
status/display hooks and plaintext handoff; revocation also rejects a pending
response after the publisher has already received an ACK. The new path joins its
owned publisher's bounded settlement before returning. It never closes the shared
signer just because a receive pane closes.

Live wrappers expose the method only for a supporting backend. A deferred signer
checks its existing account/URI/client-key binding after connection and keeps that
binding, the originating permission and selected transport in every later wire
check. An unsupported or substituted upgrade fails; it never falls back to the
old retrying publisher. The capability method is an SDK contract, not proof of an
arbitrary third-party implementation.

Regression source covers revoked/throwing decisions, late handshakes, repeated
OPEN callbacks, exact captured frames, slow peers, relay refusal, stalled close,
wrong acknowledgements and timer cleanup. Actual SDK composition source covers
late auth-URL/plaintext refusal, cancellation after ACK, deferred account/key/route
changes and unsupported backends. A separate real loopback relay/signer source
case decrypts actual NIP-44 through the explicit route and inspects the exact
signed RPC. These tests have not run; synthetic lifecycle checks are not real
transport or external signer acceptance.

The frozen Vennel compatibility qualifiers, selected KithMoot source and all
existing dispatch allowances remain unchanged. KithMoot still implements only
NIP-07 for its new incoming account pane. SDK release, consumer pinning, actual
remote-signer app composition and supported platforms remain required work.
