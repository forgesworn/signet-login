# Signet Access competitive audit

Date: 2026-06-16

This audit compares the next Signet Access release against the closest Nostr login/signing UI projects available on npm today.

## Executive take

**Signet Access is the best fit when the product needs authentication, signer access, and a server-verifiable Signet proof in one SDK.** It should not try to become every generic Nostr account widget. Its strongest position is: "drop-in access layer for apps that need a signed challenge, optional live signer, and Signet cross-device flows."

Use another tool when the app's main need is different:

| Need | Best fit | Why |
|---|---|---|
| Signet auth proof plus optional signer | Signet Access | Built around kind-21236 challenge proofs, Signet QR/redirect, NIP-07, NIP-46, Amber, and headless helpers. |
| Generic `window.nostr` shim for existing Nostr apps | `@konemono/nostr-login` | Mature `window.nostr` provider model with account switching, read-only login, signup, QR scanning, and NIP-46 relay resilience. |
| Framework-neutral web component | `nostr-mill` | Clean custom element, many login modes, strong theming surface, no required framework. |
| React app already using Nostr-WOT packages | `@nostr-wot/ui` | Session provider, hooks, CSS variables, backend auth integration, and shared signer context across the Nostr-WOT SDK. |

## Current market snapshot

| Project | Latest npm version | Last published | Core posture | Notable features |
|---|---:|---:|---|---|
| `nostr-login` | 1.7.12 | 2025-09-25 | `window.nostr` provider | NIP-46, extension login, read-only login, account switching, OAuth-like signup, OTP over DM, themes, event dispatch API. |
| `@konemono/nostr-login` | 1.15.8 | 2026-06-06 | Extended `nostr-login` fork | Multi-relay NIP-46, QR scanning for `bunker://` and `nostrconnect://`, rx-nostr relay recovery, signing retry, offline resilience, cancel support, custom NostrConnect event mode. |
| `nostr-mill` | 1.5.0 | 2026-05-20 | Zero-dependency web component | NIP-07, NIP-46, NIP-55, private key, read-only, generated identity, QR scan, CSS-variable themes, optional `window.nostr` install. |
| `@nostr-wot/ui` | 0.6.0 | 2026-05-10 | Headless React UI | Provider/hooks, modal/widget/button, NIP-07, NIP-46, generate/import, storage adapter, CSS variables, auth backend integration, profile setup. |
| `signet-login` / Signet Access | 0.10.0 | 2026-06-16 | Signet auth and signer-access SDK | Signet QR/redirect, NIP-07, NIP-46 bunker and NostrConnect, Amber, nsec fallback, kind-21236 auth proof, configurable picker, headless helpers, camera scan for `bunker://`. |

## Feature comparison

| Capability | Signet Access | `nostr-login` | `@konemono/nostr-login` | `nostr-mill` | `@nostr-wot/ui` |
|---|---|---|---|---|---|
| NIP-07 extension | Yes | Yes | Yes | Yes | Yes |
| NIP-46 paste `bunker://` | Yes | Yes | Yes | Yes | Yes |
| App-generated `nostrconnect://` QR | Yes | Yes | Yes | Yes | Yes |
| Multi-relay NIP-46 URI | Yes | Limited/unclear | Yes | Not emphasized | Yes |
| QR camera scan | `bunker://` | Not emphasized | `bunker://` and `nostrconnect://` | NIP-46 QR scan | Not emphasized |
| Amber / NIP-55 | Yes | TODO in README | Not highlighted | Yes, opt-in | No direct NIP-55 in README |
| Read-only login | No | Yes | Yes | Yes | No |
| Generate new identity | No | Yes | Yes | Yes | Yes |
| Import private key | Yes, in-memory fallback | Yes/local | Yes/local | Yes, encrypted sessionStorage | Yes, optional remember |
| Account switching | No | Yes | Yes | No | Provider can replace signer |
| Server-verifiable auth proof | Yes, kind-21236 | App-defined | App-defined | App-defined | Built-in backend auth integration |
| Headless/custom UI API | Yes | README TODO | Custom NostrConnect event mode | Programmatic API + web component | Yes, React components/hooks |
| React integration | Framework-neutral only | Framework-neutral | Framework-neutral | Framework-neutral | Native React |
| Web component | No | No | No | Yes | No |
| Storage adapter | No | localStorage model | localStorage model | sessionStorage/private-key handling | Yes |
| `window.nostr` shim | No | Yes | Yes | Optional install | No |

## Pros and cons

### Signet Access

Pros:
- Owns a clear auth proof shape instead of only returning a signer.
- Combines Signet QR/redirect with Nostr signer methods in one session model.
- Framework-neutral ESM plus standalone IIFE.
- Headless helpers now let apps build custom UX without forking modal internals.
- Advanced grouping keeps risky or power-user methods out of the default path.

Cons:
- Smaller market footprint than `nostr-login`.
- No read-only, new-identity, account-switching, or storage-adapter story yet.
- Camera scanning currently covers `bunker://`, not `nostrconnect://`.
- IIFE size increased after bundling QR decoding.
- No React provider or web component wrapper.

### `nostr-login`

Pros:
- Mature mental model: add script, get `window.nostr`.
- Broad login UX: connect, extension, read-only, local, signup, OTP.
- Useful script-tag configuration surface.

Cons:
- README lists Amber, headless, and timeout handling as TODOs.
- Older dependency stack and latest publish predates the newer active fork.
- Focus is generic Nostr provider behavior, not Signet auth proofs.

### `@konemono/nostr-login`

Pros:
- Most relevant generic competitor today.
- Strong NIP-46 reliability work: multi-relay, retries, reconnection, offline resilience.
- QR scanning covers both `bunker://` and `nostrconnect://`.
- Keeps the `window.nostr` provider model.

Cons:
- Less focused if an app wants explicit auth proof semantics.
- API is event/provider oriented, not a direct session object for auth workflows.
- UI and account features may be more than a narrow application needs.

### `nostr-mill`

Pros:
- Clean framework-neutral Web Component.
- Broadest method list, including read-only and generated identities.
- Strong theming surface and explicit security notes.
- Optional `window.nostr` installation.

Cons:
- Does not provide Signet cross-device auth or kind-21236 proof semantics.
- New identity/read-only paths can dilute a pure auth-and-signer product.
- NIP-55 needs careful host integration and is hidden by default.

### `@nostr-wot/ui`

Pros:
- Strongest React-native developer experience.
- Session provider and hooks solve app state cleanly.
- Storage adapter is a serious production feature.
- Backend auth integration and profile setup reduce app glue code.

Cons:
- React-specific.
- Best inside the Nostr-WOT package family.
- Does not position around Signet cross-device auth.

## SWOT for Signet Access

| Strengths | Weaknesses |
|---|---|
| Signet-native auth proof; multiple signer methods; framework-neutral; same session shape across auth-only and live-signer paths; cohesive with `signet-verify`, bark, and Heartwood. | Lower adoption; no storage adapter; no account switching; no read-only/new identity; no React provider; larger IIFE after QR scanner. |

| Opportunities | Threats |
|---|---|
| Own "auth proof + signer access" instead of generic login; ship wrappers for React/Web Component later; add encrypted storage adapter; deepen NIP-46 resilience; cross-sell Signet/Heartwood stack. | `@konemono/nostr-login` can absorb reliability features quickly; `nostr-mill` can become the default framework-neutral widget; `@nostr-wot/ui` can own React apps; Nostr login UX expectations may standardize around `window.nostr`. |

## Recommended roadmap

Already implemented in the 0.10.0 prep:
- Public positioning as Signet Access.
- Configurable methods and Advanced grouping.
- Multi-relay NostrConnect URI generation.
- Headless signer/auth helpers.
- Camera scan for `bunker://`.

Next high-value features:

1. **Storage adapter**  
   Let apps replace localStorage with encrypted, async, or server-backed storage. This is the strongest production gap versus `@nostr-wot/ui`.

2. **NIP-46 resilience**  
   Add reconnect/retry/backoff behavior around remote signer operations. This is the strongest reliability gap versus `@konemono/nostr-login`.

3. **Optional `window.nostr` compatibility shim**  
   Keep Signet Access session-first, but allow apps to install the active signer as `window.nostr` when migrating generic Nostr code.

4. **QR scan for `nostrconnect://`**  
   The scanner currently helps paste-bunker users. Covering both pairing directions closes the visible gap with the Konemono fork.

5. **Release wrappers, not a rewrite**  
   Add thin React and Web Component wrappers around the core API only after the storage/resilience pieces are stable.

6. **Bundle split**  
   Keep the ESM entry as the recommended path for apps. Consider `signet-login/advanced` or separate IIFE builds if standalone size becomes a barrier.

## Source links

- [`nostr-login` on npm](https://www.npmjs.com/package/nostr-login)
- [`@konemono/nostr-login` on npm](https://www.npmjs.com/package/@konemono/nostr-login)
- [`nostr-mill` on npm](https://www.npmjs.com/package/nostr-mill)
- [`@nostr-wot/ui` on npm](https://www.npmjs.com/package/@nostr-wot/ui)
