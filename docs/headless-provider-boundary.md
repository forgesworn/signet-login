# Guarded headless authentication

Consumers must require `HEADLESS_PROVIDER_EFFECT_BOUNDARY === 1` before any
initial effect. A previous SDK may accept and ignore the new arguments; function
arity and the signer's narrower per-call marker cannot establish this contract.
The export is also attached additively to `window.Signet`. That global getter
returns no positive contract if another SDK replaces any of the three headless
functions. A plain stale marker would otherwise survive an older additive SDK.
Consumers must capture the supported functions before an asynchronous decision;
the marker does not attest arbitrary cloned or subsequently modified objects.

`createNip07Signer(boundary)` fences the extension's initial `getPublicKey`
request through the existing `SignerEffectBoundary` contract. The selected
provider, discovery/signing methods and NIP-04/NIP-44 method receivers must
remain the same before the actual request and after settlement. The request
starts once inside the caller's fresh decision; waiting and joining happen
outside its native lock. Refusal after start still joins the unabortable
extension request. No provider connection or key is given to the boundary.

`createLoginAuthEvent(signer, { appName, origin, challenge, boundary })` and
`createSessionFromSigner` opt in to guarded headless proof creation. They require
the SDK `providerEffectBoundary === 1` contract, snapshot the signer and options,
and check that signer binding at each boundary. An omitted challenge is generated
inside a fresh boundary decision. A supplied challenge generates no new entropy.
Every provider signing attempt uses the boundary, including a NIP-07 retry.
The signing template includes an explicit timestamp and the exact three login
tags. The result must match that template and account, and pass independent
event-ID/signature/challenge verification. A final fresh decision fences proof
handoff. Proofs and guarded session containers are detached and frozen; the raw
signer remains borrowed and is never frozen or closed by these helpers.

Proof capture reads only the seven known event fields and the fixed three
two-part tags through data descriptors. It does not enumerate unrelated provider
fields, invoke property accessors or `toJSON`, or copy a provider verification
cache. A different valid signature, account, timestamp, content or tag order is
refused. The SDK support marker is a contract of the selected implementation;
it is not an attestation of arbitrary caller-supplied JavaScript. A signer that
advertises support but never invokes the supplied signing boundary is refused.

The caller owns the operation latch, native pending/challenge custody,
generation/account selection, resource lifetime, persistence and final session
adoption. In particular, generating a challenge under a read decision does not
retain it: a consumer that requires durable pending custody must arrange and
acknowledge that custody before authorising the signing attempt. The boundary
must freshly validate complete native state and start its callback synchronously
inside that decision, await settlement outside native locks, and recheck before
returning the same result. It must not wait for a close that joins its own call.
An already connected signer does not prove that its earlier connection was
guarded. A login proof establishes signed identity at its signed time, not
current MLS admission, room membership or independent anti-rollback continuity.

Omitting the boundary retains the existing helpers and extension discovery.
The modal, `login`, `restoreSession`, redirects, Amber and NIP-46 connection,
management and transport frames are not protected by these new arguments.
The normal signer support marker continues to describe sign/NIP-04/NIP-44
provider attempts; it does not advertise protected initial startup. Neither
the native KithMoot startup nor production foreground is mounted by this source
change. Registry reproducibility, composed browser acceptance, actual wallets,
release and physical acceptance remain separate gates.
