# Signet Access (signet-login)

Signet Access is a drop-in auth and signer-access SDK for Nostr-aware
websites. It shows one login picker across NIP-07 extensions, local/remote
Signet (QR/redirect), app-initiated NIP-46/NostrConnect, pasted bunker URIs,
Android Amber (NIP-55), and an in-memory nsec/ncryptsec fallback, then
returns a unified `SignetSigner` plus a signed kind-21236 auth proof a
server can verify.

## Commands

| Command | Purpose |
|---------|---------|
| `npm ci` | Install dependencies |
| `npm run build` | Clean, type-emit, and build the IIFE bundle into `dist/` |
| `npm test` | Run the vitest suite |
| `npm run typecheck` | Type-check without emitting |
| `npm run check:consumer-compatibility` | Run the consumer compatibility release gate |
| `npm run check:consumer-compatibility:dry-run` | Same, without dispatching |

CI (`.github/workflows/ci.yml`) runs the compatibility dry run, typecheck,
tests, build, then fails if `dist/` differs from what is checked in: rebuild
and commit `dist/` after any source change.

## Layout

- `src/`: source, one module per concern (`signers.ts`, `redirect.ts`,
  `amber.ts`, `callback.ts`, `storage.ts`, `modal.ts`, `verify.ts`,
  `types.ts`, `countdown.ts`, `platform.ts`); `signet-login.ts` is the
  package entry point.
- `dist/`: built output, checked in; CI fails if it drifts from `src/`.
- `tests/`: vitest specs, one file per `src/` module plus integration cases
  (`nip46-restore.e2e.test.ts`, `restore-client-key.test.ts`, ...).
- `examples/`: standalone HTML pages (`basic.html`, `headless.html`,
  `callback.html`, `nostrconnect-status.html`).
- `tools/`: consumer compatibility checker scripts used by CI and the
  release workflow.
- `docs/`: `amber-policy.md` (NIP-55 auth-only policy) and
  `release-app.md` (release credential setup).

## Conventions

- British English in prose and comments.
- No third-party runtime dependencies beyond `@noble/curves`,
  `@noble/hashes`, `nostr-tools`, `qrcode`, and `jsqr`.
- `dist/` is committed; always rebuild it alongside a source change.
- Public API changes need a matching entry in `src/signet-login.ts`'s
  exports and, where relevant, the `./verify` subpath.

## Pitfalls

- `nostrconnect://` and `bunker://` are different NIP-46 URI directions
  (app-initiated pairing vs signer-initiated reconnect); do not conflate
  them.
- `handleRedirectCallback` rejects legacy callbacks without a timestamp by
  default (`allowLegacyRedirectWithoutTimestamp` opts out of signature
  verification); do not change that default.
- `EphemeralSigner` and Amber/NIP-55 sessions are auth-only
  (`capabilities.canSignEvents === false`); do not treat them as live
  signers.
- Server-side verification (`signet-login/verify`) must check
  `expectedChallenge` against a nonce the server itself issued and has not
  accepted before; it keeps no state.
