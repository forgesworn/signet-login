# signet-login

[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

**Sign in with Signet** for Nostr-aware websites. One picker, three backends:

- **Browser extension** (NIP-07 — bark, Alby, nos2x, Flamingo, …)
- **Sign in with Signet** (cross-device QR via NIP-17 gift-wrap)
- **Paste bunker URI** (NIP-46 remote signer — Heartwood, nsecBunker, Amber)

Returns a unified `SignetSigner` your code can use to sign Nostr events going forward.

## Install

```bash
npm install signet-login
```

Or drop it in via CDN:

```html
<script src="https://cdn.signet.forgesworn.dev/signet-login.iife.js"></script>
```

The IIFE bundle additively extends `window.Signet` — it coexists with `signet-verify` on the same page in either load order.

## Quick start

```html
<button id="login">Sign in</button>

<script src="https://cdn.signet.forgesworn.dev/signet-login.iife.js"></script>
<script>
  document.getElementById('login').addEventListener('click', async () => {
    const session = await Signet.login({ appName: 'My Game' });
    if (!session) return;  // user cancelled

    // Sign a Nostr event with the user's chosen signer:
    const signed = await session.signer.signEvent({
      kind: 30762,
      content: '',
      tags: [
        ['game', 'my-game'],
        ['score', '12350'],
        ['p', session.pubkey],
      ],
    });
    console.log('signed:', signed);
  });
</script>
```

## API

### `Signet.login(options)`

Show the picker, return a `SignetSession` on success or `null` on cancel/timeout.

```ts
interface LoginOptions {
  appName: string;                                      // shown in modal
  challenge?: string;                                   // 64 hex; auto if omitted
  preferredMethod?: 'nip07' | 'redirect' | 'bunker';    // skip the picker
  relayUrl?: string;                                    // default wss://relay.damus.io
  theme?: 'light' | 'dark' | 'auto';                    // default 'auto'
  timeout?: number;                                     // default 120_000ms; clamped to [5k, 600k]
  signetAppOrigin?: string;                             // default https://mysignet.app
  redirectCallback?: string;                            // for same-device redirect (future)
  persist?: boolean;                                    // default true (localStorage)
}

interface SignetSession {
  pubkey: string;                  // hex
  method: 'nip07' | 'redirect' | 'bunker';
  signer: SignetSigner;
  authEvent: SignetAuthEvent;      // signed kind-21236 challenge proof
  expiresAt?: number;
  displayName?: string;
}
```

### `Signet.restoreSession(opts?)`

Restore a session from localStorage. For bunker sessions this attempts to reconnect to the stored bunker. Returns `null` if no session is stored, the session is malformed, or reconnection fails.

```js
const session = await Signet.restoreSession();
if (session?.signer.capabilities.canSignEvents) {
  // we have ongoing signing capability
}
```

### `Signet.logout(currentSession?)`

Clear stored session and close the active signer.

### `Signet.handleCallback(opts?)`

Run on your callback page when using the same-device redirect flow. Parses URL params and posts them to `window.opener` (if popup-opened), then closes the popup.

## The three signers

All three implement `SignetSigner`:

```ts
interface SignetSigner {
  readonly pubkey: string;
  readonly method: 'nip07' | 'redirect' | 'bunker';
  readonly capabilities: { canSignEvents: boolean; hasNip44: boolean };
  signEvent(template: EventTemplate): Promise<NostrEvent>;
  nip44?: { encrypt, decrypt };
  close(): Promise<void>;
}
```

| Signer | `canSignEvents` | Source |
|---|---|---|
| `Nip07Signer` | true | `window.nostr` (any NIP-07 extension) |
| `BunkerSignerImpl` | true | `nostr-tools` BunkerSigner over NIP-46 relay |
| `EphemeralSigner` | **false** | Auth-only — redirect returned only `authEvent` |

`EphemeralSigner` exists because the v0.1 redirect flow returns a single signed challenge but no ongoing-signing channel. Use `signer.capabilities.canSignEvents` to gate UI:

```js
if (session.signer.capabilities.canSignEvents) {
  enableLeaderboardPublish();
} else {
  promptUserToInstallExtensionOrPasteBunkerURI();
}
```

A future Option-B upgrade to signet-app will spawn a session-bunker per origin during the redirect approval, at which point redirect sessions will be full signers transparently. The SDK API does not change.

## Server-side verification

The client sends `session.authEvent` to your server. Verify it before granting any privileges or paying out sats:

```ts
import { verifyLogin } from 'signet-login/verify';

const result = verifyLogin(authEvent, {
  expectedChallenge: theChallengeYouIssued,
  expectedOrigin: 'https://my-game.example',
  expectedAppName: 'My Game',          // optional
  maxAgeSeconds: 300,                  // default 300
});

if (result.valid) {
  // result.pubkey is the authenticated user
} else {
  // result.error: 'invalid-signature' | 'challenge-mismatch' | 'too-old' | …
}
```

The verifier checks: schnorr signature, canonical event ID, kind=21236, challenge tag match, origin tag match, optional app tag match, freshness window (5-min default + 60s skew tolerance).

## Storage

Session data is stored in localStorage under `signet:login.*`:

| Key | Purpose |
|---|---|
| `signet:login.pubkey` | Authenticated pubkey |
| `signet:login.method` | `nip07` / `redirect` / `bunker` |
| `signet:login.authEvent` | Serialised kind-21236 auth event |
| `signet:login.bunkerUri` | Bunker URI for reconnect (bunker only) |
| `signet:login.bunkerClientSk` | Client secret key hex (bunker only) |
| `signet:login.expiresAt` | Optional expiry |
| `signet:login.displayName` | Optional persona handle |

Storage namespace is `signet:login.*` so it doesn't collide with `signet:verify.*`. `Signet.logout()` clears all login keys without touching other Signet SDKs.

## Coexistence with signet-verify

Both SDKs attach to `window.Signet` additively — load order doesn't matter:

```html
<script src=".../signet-verify.iife.js"></script>
<script src=".../signet-login.iife.js"></script>

<script>
  // age verification
  const ageResult = await Signet.verifyAge('18+');
  // login
  const session = await Signet.login({ appName: 'My App' });
</script>
```

Each SDK manages its own slice of `window.Signet` and `localStorage` namespaces.

## Bundle size

Approx **48.5 KB gzipped** (135 KB unminified). The bulk is `nostr-tools` `BunkerSigner` for NIP-46 + `signet-verify` for the cross-device QR primitive. A future split-bundle could lazy-load the bunker path to halve the initial size.

## Browser support

ES2020 baseline. Tested on modern Chrome / Firefox / Safari. Requires `localStorage`, `crypto.subtle`, `WebSocket`, and the native `<dialog>` element.

## Development

```bash
npm install
npm run build       # dist/signet-login.js (ESM) + dist/signet-login.iife.js (browser)
npm run typecheck
npm test            # vitest in jsdom
```

Examples in `examples/`:
- `basic.html` — full demo with login / sign / logout / restore
- `callback.html` — redirect-back receiver page

Build the IIFE bundle first, then serve the repo root with any static server and open `examples/basic.html`.

## Out of scope

| Excluded | Where it lives |
|---|---|
| Age verification | `signet-verify` |
| Per-game persona derivation | Heartwood RPC (reserved scope) |
| Sign-time policy clauses | Reserved (G34 NLnet Jun) |
| Generating bunker URIs | Heartwood / bark |
| Lightning, payments | Out of scope |

## License

MIT

## Related

- [signet](https://github.com/forgesworn/signet) — protocol, specs, docs
- [signet-protocol](https://www.npmjs.com/package/signet-protocol) — npm primitives
- [signet-verify](https://github.com/forgesworn/signet-verify) — age verification + cross-device auth primitives
- [bark](https://github.com/forgesworn/bark) — NIP-07 browser extension that signs via NIP-46 to Heartwood
- [Heartwood](https://github.com/forgesworn/heartwood) — self-hosted signing appliance
