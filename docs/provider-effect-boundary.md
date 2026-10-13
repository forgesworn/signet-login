# Per-call signer provider boundaries

This is an unreleased source addition. Consumers must check
`signer.providerEffectBoundary === 1` before depending on it; passing an extra
argument to an older SDK does not establish a boundary.

`signEvent`, NIP-04 and NIP-44 encrypt/decrypt accept an optional
`SignerEffectBoundary`. Its `start(provider)` method decides whether the
captured foreground may start this particular provider call. A protected
consumer must make that decision from fresh, authenticated native custody,
invoke `provider()` synchronously inside the decision, then await the
unabortable provider outside native locks and check its final handoff. The
SDK supplies this hook, not the consumer's authority or native implementation.

NIP-07 signing passes each provider attempt through the boundary, including
the existing transient retry after 250 ms. Only a rejection from the actual
provider is retryable; authorisation refusals are never classified as provider
failures by their error text. A deferred bunker forwards the
boundary to the live signer after its upgrade completes. Bunker and local
signing and encryption/decryption also call the boundary before their backend
method or local cryptography starts. Event tags are copied before yielding;
each NIP-07 retry gets a fresh copy of the original template. Provider method
receivers remain intact.

Deferred upgrades must retain the constructor's pubkey and any supplied bunker
URI and 32-byte client-key binding. URI comparison trims constructor whitespace
and otherwise preserves exact route bytes. A substituted upgrade is closed and
refused before it receives event data or plaintext; a boundary-aware call also
requires support on the upgraded signer. Owned comparison-key copies are wiped
on refusal/close without modifying the caller's source key.
The binding is checked again inside the consumer's start decision, which may
have yielded while authenticating native custody. Mismatch closure is joined
before the deferred call rejects.

Each callback starts at most once. A callback retained after its boundary
settles cannot start a provider later. A boundary cannot fabricate an omitted
provider call or substitute its result. If a boundary fails after starting a
provider, the SDK still joins that provider's settlement before rejecting.
Failures are not converted into plaintext fallbacks or successful absence.
An omitted boundary retains the existing API. Auth-only redirect and Amber
signers do not advertise live-provider boundary support.

The support marker is a versioned SDK contract, not cryptographic evidence of
an arbitrary third-party signer's behaviour. This boundary does not wrap
initial login, initial connection/restoration, transport-internal wire frames,
or NIP-46 management/rendezvous provisioning. Those need their own authorised
carrier and lifecycle checks. Requests already accepted by a provider cannot
be retracted. A provider must not await a close that joins its own unsettled
call; revoke first, settle the call, then let its external owner join it.

Automated tests exercise real local signing/NIP-44, synthetic extension
attempts, mocked bunker backends and controlled deferred upgrades. They prove
the SDK callback boundaries and joins, not native browser custody, actual
external signer/device behaviour, carrier privacy or production acceptance.
The KithMoot native foreground adapter and coordinated protected startup still
need to consume this contract. Consumer release compatibility, registry
publication and physical acceptance remain separate gates.
