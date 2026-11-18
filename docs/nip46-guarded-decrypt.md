# Guarded NIP-46 request publication

The existing `providerEffectBoundary === 1` gates a backend call. It explicitly
does not guard NIP-46 transport-internal frames or retries. A client must not use
that marker alone to enable remote decryption in a view whose revocation must
prevent queued request publication.

Supporting signers expose three optional methods under `signer.nip46`.

- `decryptNip44Guarded(peer, ciphertext, boundary)` issues `nip44_decrypt`.
- `encryptNip44Guarded(peer, plaintext, boundary)` issues `nip44_encrypt`.
- `signEventGuarded(template, boundary)` issues `sign_event`.

`Nip46RequestBoundary` extends the provider start and handoff contract with
a synchronous `current()` check and a mandatory `websocketImplementation`.
Existing decrypt callers can keep using `Nip46DecryptBoundary`. The caller
supplies the constructor for the authorised route. Each call uses the existing
paired client key and the remote signer's normal approvals.

The carrier covers the explicit request's EVENT publications. Initial login,
the shared response subscription and its reconnect frames, and other calls
use the existing connection. Requests already sent to a signer cannot be
retracted.

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

Live wrappers expose the methods only for a supporting backend. A deferred signer
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
signed RPC. These cases passed in the local full-suite execution above.
Synthetic lifecycle checks remain distinct from the real local WebSocket case;
neither establishes independent external signer or supported-device acceptance.
