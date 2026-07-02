# Changelog

## 0.14.0 (2026-07-02)

### ⚠ BREAKING CHANGES

- **redirect: reject timestamp-less redirect callbacks by default.** Previously, `handleRedirectCallback`/`consumeCallback` accepted signet-app redirect callbacks that omitted the signed event's `t` (created_at) param, silently skipping signature verification and treating the returned `pubkey` as authenticated. That default let an attacker who could reach the callback URL inject an arbitrary `pubkey` as an authenticated session. The secure behaviour is now the default: a callback missing `t` is rejected with `reason: 't-required'`. To restore the old (unverified) behaviour, pass `allowLegacyRedirectWithoutTimestamp: true` to `handleRedirectCallback` (or `allowLegacyMissingTimestamp: true` to `consumeCallback`) explicitly — only do this if you control the signet-app deployment and accept that the pubkey cannot be cryptographically verified.

### Bug Fixes

- **signers:** close the `RobustBunkerClient` (relay pool + subscription) when `getPublicKey()` fails after a NostrConnect pairing, instead of leaking it.
- **modal:** ignore a late `waitForAuthResponse` result after the user cancels or retries, so it can't overwrite a fresh attempt's status. (The underlying relay-subscription leak needs an abort hook added upstream in `signet-verify`.)
- **callback:** derive a safe `postMessage` target origin from the opener instead of defaulting to `'*'`.
- **redirect:** add a missing `catch` on a background `persistSession` call.

## 0.13.3 (2026-07-01)

### Bug Fixes

- cancel abandoned Signet handoffs



## 0.13.2 (2026-06-27)

### Bug Fixes

- harden login auth proof validation



## 0.13.1 (2026-06-21)

### Bug Fixes

- keep device picker order stable, highlight the likely option



## 0.13.0 (2026-06-21)

### Features

- make the device picker platform-aware



## 0.12.1 (2026-06-20)

### Bug Fixes

- unblock release compatibility gate



## 0.12.0 (2026-06-20)

### Features

- expand NIP-46 signer capabilities



## 0.11.1 (2026-06-19)

### Bug Fixes

- add nostrconnect status reference docs



## 0.11.0 (2026-06-19)

### Features

- expose nostrconnect status events



## 0.10.8 (2026-06-17)

### Bug Fixes

- restore bunker sessions with robust nip46 client



## 0.10.7 (2026-06-17)

### Bug Fixes

- make nostrconnect pairing relay-compatible



## 0.10.5 (2026-06-17)

### Bug Fixes

- keep nostrconnect relays separate



## 0.10.4 (2026-06-17)

### Bug Fixes

- make nostrconnect qr easier to scan



## 0.10.3 (2026-06-16)

### Bug Fixes

- persist nostrconnect sessions as bunker reconnects



## 0.10.2 (2026-06-16)

### Changed

- restore Local Signet and Remote Signet as first-class picker method names, while keeping `redirect` and `qr` as backwards-compatible aliases

## 0.10.1 (2026-06-16)

### Features

- add async `SignetStorage` adapter support for login, restore, redirect callbacks, logout, pending redirects, and the persistent NIP-46 client key

### Changed

- remove private research notes from public package docs

## 0.10.0 (2026-06-16)

### Features

- rebrand public docs/metadata around Signet Access
- add configurable picker methods, Advanced grouping, and picker-level `qr` / `nostrconnect` method selection
- emit multi-relay `nostrconnect://` URIs and configurable NIP-46 permissions
- expose headless signer/auth helpers for custom UIs
- add camera QR scanning for `bunker://` pairing codes when browser APIs are available
- add a headless custom-UI example


## 0.9.15 (2026-06-12)

### Bug Fixes

- enlarge sign-in QR to 360px + EC level H for booth scanning



## 0.9.14 (2026-06-10)

### Bug Fixes

- fall back to auth-only session on bunker-connect-timeout



## 0.9.13 (2026-06-07)

### Bug Fixes

- keep same-device signet signer alive



## 0.9.12 (2026-06-07)

### Bug Fixes

- keep same-device Signet login on relay handoff so desktop bunker tabs stay alive


## 0.9.11 (2026-06-07)

### Bug Fixes

- retry transient nip07 sign failures



## 0.9.10 (2026-06-07)

### Bug Fixes

- allow redirect callbacks to wait for bunker



## 0.9.9 (2026-06-07)

### Bug Fixes

- wait for qr bunker signer



## 0.9.8 (2026-06-07)

### Bug Fixes

- preserve qr bunker handoff



## 0.9.6 (2026-06-07)

### Bug Fixes

- keep verify dependency on published release



## 0.9.5 (2026-06-07)

### Bug Fixes

- defer bunker handoff signing readiness



## 0.9.4 (2026-06-07)

### Bug Fixes

- preserve QR bunker handoff



## 0.9.3 (2026-06-07)

### Bug Fixes

- harden modal arrow navigation



## 0.9.2 (2026-06-06)

### Bug Fixes

- track selection index for gamepad Enter (don't rely on activeElement)



## 0.9.1 (2026-06-06)

### Bug Fixes

- gamepad arrow-nav — capture-phase keydown + stopImmediatePropagation



## 0.9.0 (2026-06-06)

### Features

- gamepad-navigable login modal — arrow-key focus + synthetic Enter/Escape bridge



## 0.8.4 (2026-06-06)

### Bug Fixes

- connect the redirect bunker in the background (redirect)



## 0.8.3 (2026-06-06)

### Bug Fixes

- persist the NIP-46 client key so a bound bunker keeps auto-approving (bunker)



## 0.8.2 (2026-06-06)

### Bug Fixes

- time-box the NIP-46 connect so a dead bunker falls back to auth-only (bunker)



## 0.8.1 (2026-06-06)

### Bug Fixes

- surface bunker-upgrade fallbacks + keep the bond on a transient restore failure (login)



## 0.8.0 (2026-06-05)

### Features

- upgrade QR/relay session to a live BunkerSigner via response bunkerUri



## 0.7.2 (2026-06-05)

### Bug Fixes

- reconstruct event with only the tags signet-app actually signs (redirect)



## 0.7.1 (2026-05-15)

### Bug Fixes

- clean exit on Escape / OS back (modal)



## 0.7.0 (2026-05-10)

### Features

- NIP-55 Android sign-in via nostrsigner: redirect (amber)



## 0.6.0 (2026-05-10)

### Features

- add NostrConnect URI (app-initiated NIP-46) sign-in (modal)



## 0.5.0 (2026-05-10)

### Features

- add nsec paste sign-in (in-memory only, never persisted) (modal)



## 0.4.0 (2026-05-10)

### Features

- render real QR for cross-device Signet flow (modal)



## 0.3.0 (2026-05-10)

### Features

- consume bunker= callback param to upgrade ephemeral session (redirect)
- split Sign in with Signet into same-tab redirect + cross-device QR (modal)



## 0.2.0 (2026-05-10)

### Features

- same-tab redirect mode + handleRedirectCallback (login)
