# Signet Access

[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

Published as `signet-login`.

**Signet Access** is a drop-in auth and signer-access SDK for Nostr-aware websites. One picker, one session shape, multiple ways to prove identity and, when available, keep a live signer:

- **Local Signet** on this device, against hosted or local-dev Signet
- **Remote Signet** by cross-device QR, so a phone or second machine can approve
- **Browser extension** via NIP-07 (bark, Alby, nos2x, Flamingo, ...)
- **Connect a Nostr signer** via app-initiated NIP-46 / NostrConnect
- **Paste or scan bunker URI** for Heartwood, nsecBunker, Amber, or compatible signers
- **Sign in with Amber** via Android NIP-55
- **Paste private key** as an in-memory, advanced fallback only

Returns a unified `SignetSigner` plus a signed kind-21236 auth proof your server can verify before granting privileges.

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
  appName: string;                              // shown in modal
  challenge?: string;                           // 64 hex; auto if omitted
  preferredMethod?: LoginPickerMethod;          // skip the picker
  methods?: LoginPickerMethod[];                // picker methods, in order
  advancedMethods?: LoginPickerMethod[];        // grouped behind Advanced; [] = flat list
  relayUrl?: string;                            // default wss://relay.damus.io
  relayUrls?: string[];                         // repeated relay= params for NostrConnect
  nostrConnectPerms?: string[];                 // default sign_event + NIP-44
  onNostrConnectStatus?: NostrConnectStatusHandler;
  theme?: 'light' | 'dark' | 'auto';            // default 'auto'
  timeout?: number;                             // default 120_000ms; clamped to [5k, 600k]
  signetAppOrigin?: string;                     // default https://mysignet.app
  redirectCallback?: string;                    // for same-device redirect / Amber return
  mode?: 'relay' | 'redirect';                  // Signet delivery mode
  storage?: SignetStorage;                      // default localStorage
  persist?: boolean;                            // default true
}

interface SignetStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

type LoginPickerMethod =
  | 'nip07'
  | 'local-signet'  // same-device Signet, relay delivery
  | 'remote-signet' // cross-device Signet QR
  | 'redirect'      // legacy alias for local-signet
  | 'qr'            // legacy alias for remote-signet
  | 'bunker'        // paste bunker://
  | 'nostrconnect'  // show nostrconnect:// QR
  | 'amber'         // Android NIP-55
  | 'nsec';         // in-memory private key fallback

interface SignetSession {
  pubkey: string;                  // hex
  method: 'nip07' | 'redirect' | 'bunker' | 'nsec' | 'amber';
  signer: SignetSigner;
  authEvent: SignetAuthEvent;      // signed kind-21236 challenge proof
  expiresAt?: number;
  displayName?: string;
}
```

By default, the picker shows ordinary user-facing methods first and groups `bunker`, `nostrconnect`, and `nsec` behind **Advanced**. Control the surface per app:

```js
await Signet.login({
  appName: 'My Game',
  methods: ['local-signet', 'remote-signet', 'nip07'],
});

await Signet.login({
  appName: 'My Local Dev Game',
  preferredMethod: 'local-signet',
  signetAppOrigin: 'http://localhost:5174',
  relayUrl: 'ws://localhost:7777',
});

await Signet.login({
  appName: 'Power User Tool',
  methods: ['nip07', 'bunker', 'nostrconnect', 'nsec'],
  advancedMethods: [], // flat picker
  relayUrls: ['wss://relay.nsec.app', 'wss://relay.damus.io'],
});
```

`signetAppOrigin` defaults to `https://mysignet.app`. If your integration should launch Signet Lite specifically, pass `signetAppOrigin: 'https://lite.mysignet.app'`.

In `mode: 'redirect'`, the current tab navigates to Signet and the session is consumed later by `Signet.handleRedirectCallback()`. If the user taps Back before approving and the browser restores the original page, `login()` resolves `null` so your UI can leave its loading state.

`redirect` and `qr` remain supported picker aliases for existing apps, but new integrations should use `local-signet` and `remote-signet`.

When camera APIs are available, the bunker URI screen can scan `bunker://` QR codes directly. Paste remains the fallback.

### Headless/custom UI

Use the exported signer constructors and proof helpers when your app owns the UI:

```ts
import {
  createBunkerSigner,
  createLoginAuthEvent,
  createSessionFromSigner,
  createLocalSignerFromNsec,
} from 'signet-login';

const signer = await createBunkerSigner({
  uri: bunkerUri,
  timeoutMs: 30_000,
});

const session = await createSessionFromSigner(signer, {
  appName: 'My App',
  challenge: challengeFromServer,
  origin: 'https://my-app.example',
});

await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ authEvent: session.authEvent }),
});
```

Headless exports include `hasNip07`, `createNip07Signer`, `createBunkerSigner`, `createBunkerSignerFromNostrConnect`, `buildNostrConnectUri`, `buildBunkerUriFromNostrConnectUri`, `isBunkerUri`, `isNostrConnectUri`, `isSupportedPairingUri`, `createLocalSignerFromNsec`, `createLoginAuthEvent`, `createSessionFromSigner`, and `generateSecretKey`.
The IIFE bundle attaches the same helpers to `window.Signet`.

### NostrConnect and bunker roles

NIP-46 has two URI directions:

| URI | Producer | Consumer | Use |
|---|---|---|---|
| `nostrconnect://...` | The app / Signet Access client | Signer app scans or opens it | First pairing, where the app advertises its client pubkey, relays, requested permissions, and one-time secret |
| `bunker://...` | The signer / bunker | App connects to it | Reconnect, paste/scan bunker flows, native clients, and persisted sessions |

`createBunkerSignerFromNostrConnect()` waits for the signer response and then stores the equivalent `bunker://` reconnect URI internally, preserving the relay list and secret. This matters for apps such as Canary, Pallasite, and Axenstax: the user can pair once with NostrConnect, then `restoreSession()` can reconnect with the same stable client key instead of showing a fresh pairing request.

Signet Access is the app-side session broker. Identity creation, recovery, and derived personas belong in Signet, Heartwood, and `nsec-tree`; app integrations should consume the returned pubkey and capability flags instead of deriving identities inside the login SDK.

### NostrConnect status diagnostics

Use `onNostrConnectStatus` when your app needs a reliable progress panel, telemetry, or support diagnostics for app-initiated NostrConnect. Do not scrape the built-in modal text.

```ts
import type { NostrConnectStatus } from 'signet-login';
import { login, restoreSession } from 'signet-login';

function renderNostrConnectStatus(status: NostrConnectStatus) {
  const relay = status.relay ?? status.relays[0] ?? 'the relay';
  const method = status.method ? ` ${status.method}` : '';

  switch (status.type) {
    case 'uri-created':
      return 'Pairing code ready. Scan it with your signer.';
    case 'relay-connecting':
      return `Connecting to ${relay}...`;
    case 'relay-connected':
      return `Connected to ${relay}. Waiting for signer approval...`;
    case 'signer-seen':
      return 'Signer responded. Waiting for approval payload...';
    case 'request-sent':
      return `Sent${method} request. Waiting for signer response...`;
    case 'response-received':
      return `Signer approved${method}.`;
    case 'timeout':
      return 'Signer did not respond before the timeout.';
    case 'error':
      return status.message ?? 'NostrConnect failed.';
  }
}

const session = await login({
  appName: 'My App',
  preferredMethod: 'nostrconnect',
  relayUrls: ['wss://relay.primal.net', 'wss://relay.damus.io'],
  timeout: 120_000,
  onNostrConnectStatus(status) {
    console.log(status);
    statusText.textContent = renderNostrConnectStatus(status);
  },
});

// The same callback works for persisted bunker reconnects.
await restoreSession({
  onNostrConnectStatus(status) {
    reconnectText.textContent = renderNostrConnectStatus(status);
  },
});
```

Status events are best-effort diagnostics. Handler errors are ignored so a broken dashboard cannot break login.

| Event | Meaning | Useful fields |
|---|---|---|
| `uri-created` | The app created a `nostrconnect://` URI for the QR/link. | `uri`, `clientPubkey`, `relays`, `timeoutMs` |
| `relay-connecting` | The SDK is opening relay/subscription state. | `relays`, `clientPubkey`, `signerPubkey` |
| `relay-connected` | A relay connection succeeded. | `relay`, `relays` |
| `signer-seen` | An encrypted response event arrived from a signer pubkey. | `signerPubkey`, `clientPubkey` |
| `request-sent` | A NIP-46 request was published, such as `connect`, `sign_event`, or `nip44_encrypt`. | `method`, `requestId`, `signerPubkey` |
| `response-received` | Pairing or a NIP-46 request received a response. | `phase`, `method`, `requestId` |
| `timeout` | Pairing or a request hit its timeout. | `phase`, `method`, `requestId`, `timeoutMs`, `message` |
| `error` | Relay, subscription, publish, response, or abort failure. | `phase`, `relay`, `method`, `message`, `error` |

For support triage: no `relay-connected` usually means relay/network trouble; `signer-seen` without `response-received` usually means the signer saw the request but did not complete approval; `request-sent` without a response usually means the saved bunker session exists but the signer device is unavailable or rejecting that method.

### Custom storage

By default, Signet Access stores session state in localStorage under `signet:login.*`. Pass `storage` when you need encrypted, async, IndexedDB, server-backed, or test storage:

```js
const encryptedStorage = {
  async getItem(key) {
    const value = localStorage.getItem(key);
    return value ? await decrypt(value) : null;
  },
  async setItem(key, value) {
    localStorage.setItem(key, await encrypt(value));
  },
  async removeItem(key) {
    localStorage.removeItem(key);
  },
};

const session = await Signet.login({
  appName: 'My Game',
  storage: encryptedStorage,
});

await Signet.restoreSession({ storage: encryptedStorage });
await Signet.handleRedirectCallback({ storage: encryptedStorage });
await Signet.logout(session, { storage: encryptedStorage });
```

Use the same storage adapter for `login`, `restoreSession`, `handleRedirectCallback`, and `logout`.

For the same-tab redirect callback, current Signet deployments return the signed event timestamp and the SDK verifies the returned auth proof before accepting it. Older deployments may omit that timestamp — without it the SDK cannot rebuild the signed event and **cannot verify the signature**, so the returned `pubkey` would be unverified. **`handleRedirectCallback` rejects those callbacks by default** (`reason: 't-required'`). Only opt into accepting them if you control the signet-app deployment and knowingly accept an unverified pubkey:

```js
await Signet.handleRedirectCallback({
  storage: encryptedStorage,
  allowLegacyRedirectWithoutTimestamp: true, // ⚠️ disables signature verification — see warning above
});
```

> **Breaking change (v0.14.0):** prior versions accepted timestamp-less redirect callbacks by default. This is now secure-by-default — such callbacks are rejected unless you explicitly opt in as shown above.

This adapter is deliberately not called "Stash". `@forgesworn/stash` is the separate encrypted cloud-save vault for app data; Signet Access storage is local session/reconnect state needed before a signer is available.

### `Signet.restoreSession(opts?)`

Restore a session from configured storage. For bunker sessions this attempts to reconnect to the stored bunker. Returns `null` if no session is stored, the session is malformed, or reconnection fails.

```js
const session = await Signet.restoreSession();
if (session?.signer.capabilities.canSignEvents) {
  // we have ongoing signing capability
}
```

### `Signet.logout(currentSession?, opts?)`

Clear stored session and close the active signer.

By default, logout keeps the persistent NIP-46 client key so a previously approved bunker can recognize this browser on the next login. Pass `clearPersistentClientKey: true` when the user explicitly wants to break that pairing:

```js
await Signet.logout(session, { clearPersistentClientKey: true });
```

### `Signet.handleCallback(opts?)`

Run on your callback page when using the same-device redirect flow. Parses URL params and posts them to `window.opener` (if popup-opened), then closes the popup.

**Pass `targetOrigin`.** These params identify the signed-in user, and on the redirect-bunker handoff they include a live `bunker://...?secret=...` NIP-46 credential — a working signer, not just an identity assertion. Post them to your app's origin and nowhere else:

```js
Signet.handleCallback({
  targetOrigin: 'https://my-game.example',
});
```

If you omit it, `handleCallback` falls back to the origin of `document.referrer`, which the browser sets for a `window.open()` popup. That fallback is best-effort — referrer policy can strip it — and when no origin can be determined the params are **not** posted at all. The result's `posted` field tells you which happened, and `params` is returned either way:

```js
const { params, posted } = Signet.handleCallback({ targetOrigin: 'https://my-game.example' });
if (!posted) {
  // No opener, or no trustworthy target. Handle the params on this page instead.
}
```

Passing `targetOrigin: '*'` deliberately restores broadcasting to any opener. Don't, unless you know the callback can never carry a bunker credential.

## Signers and capabilities

All session signers implement `SignetSigner`:

```ts
interface SignetSigner {
  readonly pubkey: string;
  readonly method: 'nip07' | 'redirect' | 'bunker' | 'nsec' | 'amber';
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
| `LocalSigner` | true | In-memory nsec fallback; never persisted |
| `EphemeralSigner` | **false** | Auth-only Signet redirect / QR / Amber callback |

`EphemeralSigner` exists because some redirect-style flows return a signed challenge but no ongoing signing channel. Use `signer.capabilities.canSignEvents` to gate UI:

```js
if (session.signer.capabilities.canSignEvents) {
  enableLeaderboardPublish();
} else {
  promptUserToInstallExtensionOrPasteBunkerURI();
}
```

When Signet or a signer app returns a `bunker://` handoff, the SDK upgrades the auth-only proof into a live `BunkerSignerImpl` if the handoff connects and matches the authenticated pubkey.

Amber / NIP-55 is currently auth-only in Signet Access. It can prove identity on Android, but it does not leave the web app with a persistent signer or NIP-44 channel. Signing-required consumers should reject Amber/auth-only sessions unless a future Amber flow returns a verified live signer handoff. See `docs/amber-policy.md`.

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

### The challenge must be yours, and single-use

`verifyLogin` is stateless. It confirms the proof carries *the* challenge you passed in, but it has no way to know whether it has seen that proof before — so within the freshness window, replaying a captured auth event verifies exactly like the original. Preventing that is the caller's job:

1. **Generate the challenge on the server**, per login attempt, from a CSPRNG.
2. **Store it** against the pending login (session, cache, DB — with a TTL matching `maxAgeSeconds`).
3. **Delete it as soon as `verifyLogin` returns valid**, so a second proof bearing it is rejected.

```ts
// server
const challenge = crypto.randomBytes(32).toString('hex');
await pendingLogins.set(sessionId, challenge, { ttlSeconds: 300 });
// → hand `challenge` to the browser, which passes it to Signet.login({ challenge })

// later, when the browser posts back session.authEvent
const expected = await pendingLogins.take(sessionId);   // atomic read-and-delete
if (!expected) return reject('no-pending-login');
const result = verifyLogin(authEvent, { expectedChallenge: expected, expectedOrigin });
```

**Do not verify against a challenge the browser chose.** `login()` and `createLoginAuthEvent()` auto-generate one when `challenge` is omitted. That is fine for an app with no backend — there is nothing to replay against — but a server that accepts a client-supplied challenge has no replay protection at all, because an attacker replaying a captured auth event simply supplies the matching challenge alongside it. If a server is going to see the proof, the server issues the challenge.

Note also that the `origin` tag binds a proof to the site that requested it; it does not stop a hostile site from asking the user's signer to sign a kind-21236 event naming *your* origin. It is a binding, not a substitute for the user recognising what they approve.

## Storage

By default, session data is stored in localStorage under `signet:login.*`:

| Key | Purpose |
|---|---|
| `signet:login.pubkey` | Authenticated pubkey |
| `signet:login.method` | `nip07` / `redirect` / `bunker` / `amber` |
| `signet:login.authEvent` | Serialised kind-21236 auth event |
| `signet:login.bunkerUri` | Bunker URI for reconnect (bunker only) |
| `signet:login.bunkerClientSk` | Session client secret key hex (bunker only) |
| `signet:login.clientSk` | Persistent NIP-46 client secret key for bunker auto-approval |
| `signet:login.expiresAt` | Optional expiry |
| `signet:login.displayName` | Optional persona handle |

Storage namespace is `signet:login.*` so it doesn't collide with `signet:verify.*`. `Signet.logout()` clears session keys without touching other Signet SDKs; it clears `signet:login.clientSk` only when `clearPersistentClientKey: true` is set. Because bunker reconnect data can authorize future signing requests, apps should pair this SDK with a strict CSP and use a custom encrypted storage adapter when their threat model includes XSS on the app origin.

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

The ESM entry is approx **5.9 KB gzipped** before bundling dependencies. The standalone IIFE is approx **114.7 KB gzipped** because it includes NIP-46, Signet QR/relay support, and camera QR decoding. A future split-bundle could lazy-load advanced signer paths for smaller first-load pages.

## Browser support

ES2020 baseline. Tested on modern Chrome / Firefox / Safari. Requires `crypto.subtle`, `WebSocket`, and the native `<dialog>` element. Session persistence defaults to `localStorage`, but apps can provide a custom storage adapter.

## Development

```bash
npm install
npm run build       # dist/signet-login.js (ESM) + dist/signet-login.iife.js (browser)
npm run typecheck
npm test            # vitest in jsdom
```

Examples in `examples/`:
- `basic.html` — full demo with login / sign / logout / restore
- `headless.html` — custom UI demo using signer constructors and proof helpers
- `nostrconnect-status.html` — NostrConnect pairing with a diagnostic event log
- `callback.html` — redirect-back receiver page

Build the IIFE bundle first, then serve the repo root with any static server and open an example page.

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
