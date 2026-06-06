# Changelog

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


