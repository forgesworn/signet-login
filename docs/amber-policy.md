# Amber Policy

Amber / NIP-55 is supported by `signet-login` as an Android auth-only flow.

Current policy:

- `signet-login` may show Amber on Android and consume the returned signed auth event.
- Amber sessions use `method: "amber"` and an `EphemeralSigner`.
- Amber sessions must report `signer.capabilities.canSignEvents === false`.
- Amber sessions must not claim NIP-44 support.
- Consumers that require event signing or NIP-44 must reject Amber/auth-only sessions at their boundary.
- Canary must not expose Amber as a full signer path unless the flow returns or upgrades to a live signer with NIP-44.

Reason:

NIP-55 signs by Android intent handoff. It proves identity for the returned auth event, but it does not leave the web app with a persistent signing channel. Asking the user to round-trip every later event through an Android intent would be fragile and confusing for apps such as Canary, Pallasite, Axenstax, and Forge Realms.

What would change this policy:

- Amber or another NIP-55-compatible app returns a live `bunker://` handoff that can be verified against the authenticated pubkey.
- The handoff supports `sign_event`, `nip44_encrypt`, and `nip44_decrypt`.
- Canary has a regression proving login, reload, restore, and NIP-44 encrypt/decrypt all work through that path.

Until then, Amber remains SDK-covered but not a production full-signer route for signing-required consumers.
