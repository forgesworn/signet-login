/**
 * Signet Access SDK — Sign in with Signet for Nostr-aware websites.
 *
 * ESM / bundler usage:
 *   import { login, restoreSession, logout } from 'signet-login';
 *
 * Script-tag / IIFE usage (additively extends `window.Signet`):
 *   <script src="https://cdn.signet.forgesworn.dev/signet-login.iife.js"></script>
 *   <script>
 *     const session = await Signet.login({ appName: 'Asteroid Sats' });
 *   </script>
 *
 * The IIFE bundle does NOT overwrite `window.Signet` — it augments whatever is
 * already there (so `signet-verify.iife.js` and `signet-login.iife.js` coexist
 * in either load order on the same page).
 */

export type {
  NostrEvent,
  EventTemplate,
  LoginMethod,
  LoginPickerMethod,
  SignerCapabilities,
  SignerEffectBoundary,
  Nip46DecryptBoundary,
  Nip07DiscoveryBoundary,
  SignetSigner,
  SignetAuthEvent,
  SignetSession,
  NostrConnectStatus,
  NostrConnectStatusHandler,
  NostrConnectStatusPhase,
  NostrConnectStatusType,
  LoginOptions,
  RestoreOptions,
  SignetStorage,
} from './types.js';

import type {
  SignetSigner,
  LoginOptions,
  RestoreOptions,
  SignetSession,
  SignetAuthEvent,
  SignetStorage,
  SignerEffectBoundary,
} from './types.js';
import { DEFAULTS } from './types.js';
import { withProviderEffect } from './effects.js';
/** Versioned SDK contract for guarded NIP-07 discovery and the headless proof
 * helpers. It does not advertise guarded modal, restore or carrier startup. */
export const HEADLESS_PROVIDER_EFFECT_BOUNDARY = 1 as const;
/** NIP-07 discovery preflight precedes the caller's native decision. */
export const HEADLESS_NIP07_DISCOVERY_BOUNDARY = 1 as const;
/** Opt-in NIP-07 wrappers capture provider callables and receivers once. */
export const HEADLESS_NIP07_PINNED_PROVIDER_CALLS = 1 as const;
/** Exact SDK-local cache metadata identity for strict event adapters. This
 * symbol is not signature verification or permission to invoke a signer. */
import { verifiedSymbol } from 'nostr-tools/pure';
export const SIGNET_VERIFIED_EVENT_SYMBOL: typeof verifiedSymbol = verifiedSymbol;
import { showLoginModal } from './modal.js';
import {
  saveSessionToStorage,
  assertRequiredSessionStorage,
  loadSessionFromStorage,
  clearSessionFromStorage,
  bytesToHexLocal,
  decodeClientSecretKey,
  loadOrCreatePersistentClientSkFromStorage,
  clearPersistentClientSkFromStorage,
  replaceStoredBunkerUri,
} from './storage.js';
import {
  hasNip07,
  createNip07Signer,
  createNip07SignerWithDiscoveryBoundary,
  createPinnedNip07SignerWithDiscoveryBoundary,
  createBunkerSigner,
  createBunkerSignerFromNostrConnect,
  buildNostrConnectUri,
  buildBunkerUriFromNostrConnectUri,
  isBunkerUri,
  isNostrConnectUri,
  isSupportedPairingUri,
  createLocalSignerFromNsec,
  isEncryptedNsec,
  generateSecretKey,
  EphemeralSigner,
  DeferredBunkerSigner,
  Nip07Signer,
  BunkerSignerImpl,
  LocalSigner,
} from './signers.js';
import { consumeAmberCallbackFromStorage, type ConsumeAmberResult } from './amber.js';

import { handleCallback as handlePopupCallback } from './callback.js';
import { consumeCallbackFromStorage, startRedirect } from './redirect.js';
import type { ConsumeCallbackResult } from './redirect.js';
import { assertValidLoginAuthEvent } from './verify.js';
export type { PinnedNip07Signer } from './signers.js';
export type { CallbackResult, HandleCallbackOptions } from './callback.js';
export type { ConsumeCallbackResult } from './redirect.js';
export type { ConsumeAmberResult } from './amber.js';
export { isAndroid } from './amber.js';
export {
  hasNip07,
  createNip07Signer,
  createNip07SignerWithDiscoveryBoundary,
  createPinnedNip07SignerWithDiscoveryBoundary,
  createBunkerSigner,
  createBunkerSignerFromNostrConnect,
  buildNostrConnectUri,
  buildBunkerUriFromNostrConnectUri,
  isBunkerUri,
  isNostrConnectUri,
  isSupportedPairingUri,
  createLocalSignerFromNsec,
  isEncryptedNsec,
  generateSecretKey,
  Nip07Signer,
  BunkerSignerImpl,
  LocalSigner,
};

/**
 * Cap the redirect-bunker auto-pair handshake. The `bunker://` URI signet-app
 * appends is best-effort and may be unreachable on arrival — most notably when
 * it points at signet-app's own in-page NIP-46 server, which the same-tab
 * navigation back to the consumer has already torn down, so the connect can
 * never complete. Bound it so boot degrades to the ephemeral auth-only session
 * in a few seconds instead of hanging the consumer on a blank screen.
 */
const REDIRECT_BUNKER_CONNECT_TIMEOUT_MS = 8_000;

export interface HandleRedirectCallbackOptions {
  /**
   * Await the returned `bunker://` handoff before resolving the callback.
   *
   * Default is false so identity-only consumers can paint immediately and let
   * a deferred bunker warm in the background. Signing-required consumers
   * should set this true and reject auth-only returns at their boundary.
   */
  waitForBunker?: boolean;
  /**
   * Storage backend for pending redirect consumption and session persistence.
   * Must match the backend passed to `login({ mode: 'redirect', storage })`.
   */
  storage?: SignetStorage;
  /**
   * Older signet-app redirect callbacks omitted the signed event timestamp,
   * which prevents client-side signature verification — the resulting
   * session's `pubkey` is UNVERIFIED. Secure by default: `false`/unset
   * rejects those callbacks (`reason: 't-required'`). Set `true` only if
   * you control the signet-app deployment and knowingly accept sessions
   * whose pubkey cannot be cryptographically checked.
   */
  allowLegacyRedirectWithoutTimestamp?: boolean;
}

export interface CreateLoginAuthEventOptions {
  /** Required. Bound into the auth event's `app` tag. */
  appName: string;
  /** Optional 64-hex challenge. Auto-generated if omitted. */
  challenge?: string;
  /** Origin to bind into the proof. Defaults to `window.location.origin`. */
  origin?: string;
  /** Opt in to guarded headless authentication: fence challenge entropy and
   * every signing attempt, require the SDK provider-boundary contract, and
   * return a detached, verified proof. The caller still owns initial connection,
   * native pending/session custody, operation lifetime and final adoption.
   * This option does not protect the modal, restore or redirect paths. */
  boundary?: SignerEffectBoundary;
}

export interface LogoutOptions {
  /** Storage backend to clear. Defaults to localStorage. */
  storage?: SignetStorage;
  /**
   * Also clear the persistent NIP-46 client key used for bunker auto-approval.
   * Default false preserves the existing "logout does not break pairing" behavior.
   */
  clearPersistentClientKey?: boolean;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Show the login picker and resolve to a SignetSession on success, or null on
 * cancel / timeout.
 *
 * When `mode: 'redirect'` is set, the picker is skipped entirely — the current
 * tab navigates to signet-app. Callers should treat the returned promise as
 * "fire and forget" in the normal navigation case and call
 * `Signet.handleCallback()` on the next page load to receive the session. If
 * the user backs out and the browser restores the original page, the promise
 * resolves null so the caller can leave its loading state. The other login
 * methods (NIP-07, bunker) don't use redirect at all and are unaffected by this
 * option.
 */
export async function login(opts: LoginOptions): Promise<SignetSession | null> {
  assertRequiredSessionStorage(opts.storage);
  if (opts.storage?.required && opts.preferredMethod === 'nsec') throw new Error('required-storage-nsec-is-memory-only');
  if (opts.storage?.required && opts.persist === false) throw new Error('required-storage-session-persistence-required');
  // Redirect mode short-circuits the picker — the user is going to signet-app.
  // We don't gate on preferredMethod here: redirect mode implies the consumer
  // wants the Sign in with Signet method, which is the only method that uses
  // navigation. (NIP-07 and bunker resolve in-tab regardless of mode.)
  if (opts.mode === 'redirect') {
    if (typeof window === 'undefined') {
      throw new Error('signet-login: redirect mode requires a browser environment');
    }
    const challenge = opts.challenge ?? generateChallenge();
    if (!/^[0-9a-f]{64}$/i.test(challenge)) throw new Error('challenge-must-be-64-hex');
    if (!opts.appName || opts.appName.length === 0) throw new Error('appName-required');
    if (opts.appName.length > 64) throw new Error('appName-too-long');
    return startRedirect({
      appName: opts.appName,
      challenge: challenge.toLowerCase(),
      origin: window.location.origin,
      signetAppOrigin: opts.signetAppOrigin ?? DEFAULTS.signetAppOrigin,
      ...(opts.redirectCallback !== undefined ? { redirectCallback: opts.redirectCallback } : {}),
      ...(opts.storage !== undefined ? { storage: opts.storage } : {}),
    });
  }

  const session = await showLoginModal(opts);
  if (!session) return null;

  if (opts.persist !== false) {
    await persistSession(session, opts.storage);
  }

  return session;
}

/**
 * Headless helper for custom UIs. Given any SignetSigner, sign the same
 * kind-21236 login proof the built-in picker uses.
 */
export async function createLoginAuthEvent(
  signer: SignetSigner,
  opts: CreateLoginAuthEventOptions,
): Promise<SignetAuthEvent> {
  const boundary = opts.boundary;
  if (boundary !== undefined) return createGuardedLoginAuthEvent(signer, {
    appName: opts.appName, challenge: opts.challenge, origin: opts.origin, boundary,
  });
  const { appName } = opts;
  if (!appName || appName.length === 0) throw new Error('appName-required');
  if (appName.length > 64) throw new Error('appName-too-long');
  const challenge = opts.challenge ?? generateChallenge();
  if (!/^[0-9a-f]{64}$/i.test(challenge)) throw new Error('challenge-must-be-64-hex');
  const origin = opts.origin ?? (typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  if (!origin) throw new Error('origin-required');

  const authEvent = await signer.signEvent({
    kind: 21236,
    content: '',
    tags: [
      ['challenge', challenge.toLowerCase()],
      ['origin', origin],
      ['app', appName],
    ],
  }) as SignetAuthEvent;

  return assertValidLoginAuthEvent(authEvent, {
    expectedChallenge: challenge.toLowerCase(),
    expectedOrigin: origin,
    expectedAppName: appName,
    expectedPubkey: signer.pubkey,
  });
}

/** Capture only the exact requested proof fields, without provider accessors,
 * toJSON hooks or the nostr-tools verification cache. This path signs one
 * fixed three-tag template; accepting a different valid event is not enough. */
function captureGuardedLoginProof(raw: unknown, template: Required<import('./types.js').EventTemplate>, pubkey: string): SignetAuthEvent {
  const invalid = (): never => { throw new Error('auth-event-invalid: guarded-proof-template'); };
  if (!raw || typeof raw !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) invalid();
  const read = (name: string): unknown => {
    const field = Object.getOwnPropertyDescriptor(raw, name);
    if (!field || !Object.prototype.hasOwnProperty.call(field, 'value')) return invalid();
    return field.value;
  };
  const id = read('id'), key = read('pubkey'), sig = read('sig');
  if (typeof id !== 'string' || !/^[0-9a-f]{64}$/i.test(id) || key !== pubkey ||
      typeof sig !== 'string' || !/^[0-9a-f]{128}$/i.test(sig) ||
      read('kind') !== template.kind || read('content') !== template.content || read('created_at') !== template.created_at) invalid();
  const tags = read('tags');
  const array = (value: unknown, length: number): unknown[] => {
    if (!Array.isArray(value)) invalid();
    if (Object.getOwnPropertyDescriptor(value, 'length')?.value !== length) invalid();
    return value as unknown[];
  };
  const rows = array(tags, 3);
  const copied = template.tags.map((tag, index) => {
    const row = Object.getOwnPropertyDescriptor(rows, String(index));
    if (!row || !Object.prototype.hasOwnProperty.call(row, 'value')) return invalid();
    const parts = array(row.value, 2);
    for (let i = 0; i < 2; i++) {
      const part = Object.getOwnPropertyDescriptor(parts, String(i));
      if (!part || !Object.prototype.hasOwnProperty.call(part, 'value') || part.value !== tag[i]) invalid();
    }
    return Object.freeze([...tag]) as unknown as string[];
  });
  return Object.freeze({ id, pubkey: key, sig, kind: 21236, content: '', created_at: template.created_at,
    tags: Object.freeze(copied) as unknown as string[][] }) as SignetAuthEvent;
}

async function createGuardedLoginAuthEvent(signer: SignetSigner, opts: CreateLoginAuthEventOptions): Promise<SignetAuthEvent> {
  // Snapshot inputs and signer identity before any asynchronous decision.
  const { appName, origin: suppliedOrigin, challenge: suppliedChallenge, boundary } = opts;
  if (typeof boundary?.start !== 'function') throw new Error('invalid-signer-effect-boundary');
  const pubkey = signer.pubkey, method = signer.method, sign = signer.signEvent;
  if (signer.providerEffectBoundary !== 1 || typeof sign !== 'function') throw new Error('signer-effect-boundary-unsupported');
  if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('invalid-pubkey-from-signer');
  if (typeof appName !== 'string' || !appName) throw new Error('appName-required');
  if (appName.length > 64) throw new Error('appName-too-long');
  const origin = suppliedOrigin ?? (typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
  if (typeof origin !== 'string' || !origin || origin.length > 1024) throw new Error('origin-required-or-too-long');
  if (suppliedChallenge !== undefined && (typeof suppliedChallenge !== 'string' || !/^[0-9a-f]{64}$/i.test(suppliedChallenge))) {
    throw new Error('challenge-must-be-64-hex');
  }
  const check = () => {
    if (signer.pubkey !== pubkey || signer.method !== method || signer.signEvent !== sign || signer.providerEffectBoundary !== 1) {
      throw new Error('login-signer-changed');
    }
  };
  const guarded: SignerEffectBoundary = {
    async start<T>(provider: () => Promise<T>): Promise<T> {
      check();
      const value = await withProviderEffect(boundary, () => { check(); return provider(); });
      check();
      return value;
    },
  };
  const challenge = suppliedChallenge ?? await withProviderEffect(guarded, () => Promise.resolve(generateChallenge()));
  const template = {
    kind: 21236, created_at: Math.floor(Date.now() / 1000), content: '',
    tags: [['challenge', challenge.toLowerCase()], ['origin', origin], ['app', appName]],
  };
  // Keep a separate expected template: a provider may mutate its argument.
  let signingStarts = 0;
  const signingBoundary: SignerEffectBoundary = {
    start: provider => guarded.start(() => { signingStarts++; return provider(); }),
  };
  const authEvent = captureGuardedLoginProof(await sign.call(signer, {
    ...template, tags: template.tags.map(tag => [...tag]),
  }, signingBoundary), template, pubkey);
  if (signingStarts === 0) throw new Error('signer-effect-boundary-not-used');
  check();
  const verified = assertValidLoginAuthEvent(authEvent, {
    expectedChallenge: challenge.toLowerCase(), expectedOrigin: origin, expectedAppName: appName, expectedPubkey: pubkey,
  });
  return withProviderEffect(guarded, () => Promise.resolve(verified));
}

/**
 * Headless helper for custom UIs. Builds the same SignetSession shape returned
 * by `login()` from a signer the caller already obtained.
 */
export async function createSessionFromSigner(
  signer: SignetSigner,
  opts: CreateLoginAuthEventOptions,
): Promise<SignetSession> {
  const boundary = opts.boundary;
  if (boundary === undefined) {
    const authEvent = await createLoginAuthEvent(signer, { appName: opts.appName, challenge: opts.challenge, origin: opts.origin });
    return { pubkey: signer.pubkey, method: signer.method, signer, authEvent };
  }
  const pubkey = signer.pubkey, method = signer.method, sign = signer.signEvent;
  const authEvent = await createGuardedLoginAuthEvent(signer, {
    appName: opts.appName, challenge: opts.challenge, origin: opts.origin, boundary,
  });
  if (authEvent.pubkey !== pubkey || signer.pubkey !== pubkey || signer.method !== method || signer.signEvent !== sign || signer.providerEffectBoundary !== 1) {
    throw new Error('login-signer-changed');
  }
  const session = {
    pubkey,
    method,
    signer,
    authEvent,
  };
  return Object.freeze(session);
}

/**
 * Generate a 64-hex random challenge. Mirrors the modal's helper but lives at
 * the module level so the redirect path can call it without pulling the modal
 * into the bundle when only `mode: 'redirect'` is used.
 */
function generateChallenge(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Try to restore a session from localStorage. Returns null if no session is
 * stored or it's malformed/expired.
 *
 * For bunker sessions, attempts to reconnect using the stored URI + client SK.
 * If the bunker is unreachable, returns null and clears the stored session.
 */
export async function restoreSession(opts?: RestoreOptions): Promise<SignetSession | null> {
  const stored = await loadSessionFromStorage(opts?.storage);
  if (!stored) return null;

  let authEvent: SignetAuthEvent;
  try {
    authEvent = JSON.parse(stored.authEventJson);
  } catch {
    await clearSessionFromStorage(opts?.storage);
    return null;
  }

  if (stored.method === 'nip07') {
    if (!hasNip07()) {
      // Extension was uninstalled — return ephemeral identity-only session
      const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
      return {
        pubkey: stored.pubkey,
        method: 'redirect', // downgrade — caller sees "no signing"
        signer: ephemeral,
        authEvent,
      };
    }
    try {
      const signer = await createNip07Signer();
      // Verify the same pubkey is selected — extension may have switched accounts
      if (signer.pubkey !== stored.pubkey) {
        await clearSessionFromStorage(opts?.storage);
        return null;
      }
      return {
        pubkey: stored.pubkey,
        method: 'nip07',
        signer,
        authEvent,
      };
    } catch {
      await clearSessionFromStorage(opts?.storage);
      return null;
    }
  }

  if (stored.method === 'bunker') {
    if (opts?.reconnectBunker === false) {
      const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
      return {
        pubkey: stored.pubkey,
        method: 'redirect',
        signer: ephemeral,
        authEvent,
      };
    }
    if (!stored.bunkerUri || !stored.bunkerClientSkHex) {
      console.warn('[signet-login] restore: stored bunker session has no reconnect creds (bunkerUri/clientSk) — it was an auth-only login. Clearing.');
      await clearSessionFromStorage(opts?.storage);
      return null;
    }
    const clientSecretKey = decodeClientSecretKey(stored.bunkerClientSkHex);
    if (!clientSecretKey) {
      console.warn('[signet-login] restore: stored bunker clientSk is corrupt — clearing.');
      await clearSessionFromStorage(opts?.storage);
      return null;
    }
    let signer: BunkerSignerImpl;
    try {
      // Restore uses the session's client key, never a newly generated one.
      signer = await createBunkerSigner({
        uri: stored.bunkerUri, clientSecretKey, onStatus: opts?.onNostrConnectStatus,
      });
    } catch (err) {
      console.warn('[signet-login] restore: bunker reconnect failed — keeping creds for the next retry.', err);
      return null;
    }
    if (signer.pubkey !== stored.pubkey) {
      await signer.close().catch(() => {});
      if (opts?.storage?.required) throw new Error('required-storage-restored-signer-mismatch');
      console.warn('[signet-login] restore: reconnected bunker pubkey mismatch — clearing session');
      await clearSessionFromStorage(opts?.storage);
      return null;
    }
    // The signer moved this session to other relays: keep them for the next
    // restore. Advisory, so a failed or conflicting write never fails restore.
    const reconnectUri = signer.reconnectBunkerUri;
    if (reconnectUri !== stored.bunkerUri) {
      await replaceStoredBunkerUri(stored.bunkerUri, reconnectUri, opts?.storage).catch(() => {});
    }
    return { pubkey: stored.pubkey, method: 'bunker', signer, authEvent };
  }

  // method === 'redirect' or 'amber' — both restore as ephemeral (auth-only).
  // Preserve the original method so consumers can still distinguish how the
  // user originally authenticated.
  const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
  const session: SignetSession = {
    pubkey: stored.pubkey,
    method: stored.method,
    signer: ephemeral,
    authEvent,
  };
  if (stored.displayName) session.displayName = stored.displayName;
  return session;
}

/**
 * Popup-style callback receiver. Use on the page that signet-app redirects
 * a popup to. Parses URL params and posts them to `window.opener`, then
 * closes the popup. Returns the raw params for non-popup contexts.
 *
 * For the same-tab redirect flow (`mode: 'redirect'` on `login()`), use
 * `Signet.handleRedirectCallback()` instead — that one validates against the
 * persisted pending state and returns a fully-formed `SignetSession`.
 */
export const handleCallback = handlePopupCallback;

/**
 * Same-tab redirect callback receiver. Call once on app boot, before
 * `restoreSession()`, to consume an incoming `?pubkey&signature&eventId`
 * payload from signet-app.
 *
 * Behaviour:
 *
 *   - `'session'`: validates the round-trip against the pending state saved
 *     by `login({ mode: 'redirect' })`, builds and persists a SignetSession
 *     (so `restoreSession()` finds it next time), and strips the auth params
 *     from the URL via `history.replaceState`. The returned session uses an
 *     `EphemeralSigner` — `signer.capabilities.canSignEvents` is false. Pair
 *     with NIP-07 / bunker if you need ongoing signing.
 *
 *   - `'denied'`: signet-app reported the user rejected the request.
 *
 *   - `'no-callback'`: no auth params on the URL — the typical case on most
 *     page loads. Idempotent: a second call after success also returns this.
 *
 *   - `'invalid'`: params present but failed validation. `reason` is a
 *     machine-readable token (`origin-mismatch`, `pending-stale`,
 *     `pubkey-malformed`, …). Pending state is cleared either way so a stale
 *     URL can't poison the next attempt.
 *
 * The returned shape is intentionally tagged so consumers can distinguish
 * "user denied" from "no callback" without inspecting null. Persistence on
 * success uses the same storage layer as relay-mode sessions, so downstream
 * code that consumes `restoreSession()` doesn't need to care which path
 * authenticated the user.
 */
export async function handleRedirectCallback(options: HandleRedirectCallbackOptions = {}): Promise<ConsumeCallbackResult | ConsumeAmberResult> {
  assertRequiredSessionStorage(options.storage);
  // Try Amber first — its callback shape (event= param) is disjoint from
  // signet-app's (pubkey/signature/eventId), so the order doesn't matter
  // for valid callbacks. Picking Amber first only affects the 'no-callback'
  // → 'no-callback' fall-through, where checking either side first is fine.
  const amberResult = await consumeAmberCallbackFromStorage(options.storage);
  if (amberResult.kind === 'session') {
    await persistSession(amberResult.session, options.storage);
    return amberResult;
  }
  if (amberResult.kind !== 'no-callback') {
    return amberResult;
  }

  const result = await consumeCallbackFromStorage(options.storage, {
    allowLegacyMissingTimestamp: options.allowLegacyRedirectWithoutTimestamp,
  });
  if (result.kind !== 'session') return result;

  // Optional redirect-bunker upgrade. signet-app appends a `bunker://` URI
  // when the user authorised the redirect login; it lets us swap the auth-only
  // `EphemeralSigner` for a real signing bunker. The connect runs in the
  // BACKGROUND so this callback resolves immediately — awaiting the up-to-8s
  // handshake here blocked the consumer's first paint on a blank screen
  // (signet-app-internal: pallasite empty-screen-on-signin). DeferredBunkerSigner
  // awaits the connect on the first signEvent/nip44 call; if it fails the
  // session is still valid for identity proof.
  if (result.bunkerUri) {
    const expected = result.session.pubkey;
    const authEvent = result.session.authEvent;
    const displayName = result.session.displayName;
    const clientSecretKey = await loadOrCreatePersistentClientSkFromStorage(options.storage);
    const upgrade: Promise<BunkerSignerImpl | null> = createBunkerSigner({
      uri: result.bunkerUri,
      clientSecretKey,
      timeoutMs: REDIRECT_BUNKER_CONNECT_TIMEOUT_MS,
    })
      .catch((err): null => {
        clientSecretKey.fill(0);
        console.warn('[signet-login] redirect upgrade: createBunkerSigner failed — staying auth-only (no live signing). Reconnect/relay issue or signer device unreachable.', err);
        return null;
      })
      .then(async (bunkerSigner): Promise<BunkerSignerImpl | null> => {
        if (!bunkerSigner) return null;
        // Sanity: the bunker must sign as the same pubkey the redirect
        // authenticated. A mismatch means a misconfigured deployment or a
        // tampered URL — drop back to auth-only rather than silently swapping
        // identity under the consumer's feet.
        if (bunkerSigner.pubkey.toLowerCase() !== expected.toLowerCase()) {
          console.warn('[signet-login] redirect upgrade: bunker pubkey mismatch — staying auth-only (cannot sign)', { connected: bunkerSigner.pubkey, expected });
          await bunkerSigner.close().catch(() => {});
          clientSecretKey.fill(0);
          return null;
        }
        // Live now — re-persist with real bunker creds so the next load
        // restores a connected signer instead of an auth-only stub.
        const liveSession: SignetSession = { pubkey: expected, method: 'bunker', signer: bunkerSigner, authEvent };
        if (displayName) liveSession.displayName = displayName;
        if (options.storage?.required) {
          try { await persistSession(liveSession, options.storage); }
          catch (error) { clientSecretKey.fill(0); throw error; }
        }
        else void persistSession(liveSession, options.storage).catch(() => {});
        return bunkerSigner;
      });

    // Required custody has no background session writer: await the one live
    // receipt and propagate its rejection before exposing any session.
    if (options.waitForBunker || options.storage?.required) {
      const bunkerSigner = await upgrade;
      if (bunkerSigner) {
        const liveSession: SignetSession = { pubkey: expected, method: 'bunker', signer: bunkerSigner, authEvent };
        if (displayName) liveSession.displayName = displayName;
        if (!options.storage?.required) await persistSession(liveSession, options.storage);
        return { kind: 'session', session: liveSession };
      }
      if (options.storage?.required) {
        await persistSession(result.session, options.storage);
        return result;
      }
    }

    const session: SignetSession = {
      pubkey: expected,
      method: 'bunker',
      signer: new DeferredBunkerSigner(expected, authEvent, upgrade, result.bunkerUri, clientSecretKey, false),
      authEvent,
    };
    if (displayName) session.displayName = displayName;
    // Persist the deferred bunker session now so a reload mid-handshake keeps
    // the bunker URI + stable client key and restoreSession can reconnect.
    // The background upgrade re-persists with the live signer on success.
    await persistSession(session, options.storage);
    return { kind: 'session', session };
  }

  console.warn('[signet-login] redirect login carried no bunkerUri — auth-only ephemeral (cannot sign). The signer device must enable its NIP-46 server to return a bunker:// URI.');
  await persistSession(result.session, options.storage);
  return result;
}

/**
 * Clear the stored session and close the active signer.
 */
export async function logout(currentSession?: SignetSession, opts?: LogoutOptions): Promise<void> {
  if (currentSession) {
    try {
      const remoteLogout = currentSession.signer.nip46?.logout();
      if (remoteLogout) {
        await Promise.race([
          remoteLogout,
          new Promise(resolve => setTimeout(resolve, 1_500)),
        ]);
      }
    } catch { /* ignore */ }
    try { await currentSession.signer.close(); } catch { /* ignore */ }
  }
  await clearSessionFromStorage(opts?.storage);
  if (opts?.clearPersistentClientKey) {
    await clearPersistentClientSkFromStorage(opts.storage);
  }
}

// ── Persistence helpers (internal) ────────────────────────────────────────────

async function persistSession(session: SignetSession, storage?: SignetStorage): Promise<void> {
  // nsec sessions are deliberately in-memory only — writing the pubkey or
  // even the method to storage would leak that this user has used a paste
  // path. Reload lands the user back on the picker, which is the contract
  // we surface in runNsecFlow's warning copy.
  if (session.method === 'nsec') {
    if (storage?.required) throw new Error('required-storage-nsec-is-memory-only');
    return;
  }

  const payload: Parameters<typeof saveSessionToStorage>[0] = {
    pubkey: session.pubkey,
    method: session.method,
    authEventJson: JSON.stringify(session.authEvent),
  };

  if (session.method === 'bunker') {
    // Cast: in bunker mode, the signer is a BunkerSignerImpl with bunkerUri + clientSecretKey
    const bunkerSigner = session.signer as unknown as {
      bunkerUri?: string;
      reconnectBunkerUri?: string;
      clientSecretKey?: Uint8Array;
    };
    if (bunkerSigner.bunkerUri && bunkerSigner.clientSecretKey instanceof Uint8Array) {
      // Prefer the relays the signer moved this session to (switch_relays),
      // so the next restore reaches the relay the signer keeps serving.
      payload.bunkerUri = bunkerSigner.reconnectBunkerUri || bunkerSigner.bunkerUri;
      payload.bunkerClientSkHex = bytesToHexLocal(bunkerSigner.clientSecretKey);
    }
  }

  if (session.expiresAt !== undefined) payload.expiresAt = session.expiresAt;
  if (session.displayName !== undefined) payload.displayName = session.displayName;

  try {
    await saveSessionToStorage(payload, storage);
  } catch (error) {
    if (storage?.required) {
      try { await session.signer.close?.(); } catch { /* Closing cannot waive the failed receipt. */ }
    }
    throw error;
  }
}

// ── Auto-attach to window.Signet (additive) ───────────────────────────────────

if (typeof window !== 'undefined') {
  // Never overwrite — additive only. Coexists with signet-verify on the same page.
  const existing = (window as unknown as { Signet?: Record<string, unknown> }).Signet;
  const SignetGlobal = existing ?? {};
  Object.assign(SignetGlobal, {
    SIGNET_VERIFIED_EVENT_SYMBOL,
    login,
    hasNip07,
    createNip07Signer,
    createNip07SignerWithDiscoveryBoundary,
    createPinnedNip07SignerWithDiscoveryBoundary,
    createBunkerSigner,
    createBunkerSignerFromNostrConnect,
    buildNostrConnectUri,
    buildBunkerUriFromNostrConnectUri,
    isBunkerUri,
    isNostrConnectUri,
    isSupportedPairingUri,
    createLocalSignerFromNsec,
    generateSecretKey,
    createLoginAuthEvent,
    createSessionFromSigner,
    restoreSession,
    logout,
    handleCallback,
    handleRedirectCallback,
  });
  // An older additive SDK can later replace these functions without removing
  // new properties. Never leave a stale positive contract beside old methods.
  Object.defineProperty(SignetGlobal, 'HEADLESS_NIP07_PINNED_PROVIDER_CALLS', {
    configurable: true, enumerable: true,
    get: () => SignetGlobal.createPinnedNip07SignerWithDiscoveryBoundary === createPinnedNip07SignerWithDiscoveryBoundary ? 1 : undefined,
    set: () => {},
  });
  Object.defineProperty(SignetGlobal, 'HEADLESS_NIP07_DISCOVERY_BOUNDARY', {
    configurable: true, enumerable: true,
    get: () => SignetGlobal.createNip07SignerWithDiscoveryBoundary === createNip07SignerWithDiscoveryBoundary ? 1 : undefined,
    set: () => {},
  });
  Object.defineProperty(SignetGlobal, 'HEADLESS_PROVIDER_EFFECT_BOUNDARY', {
    configurable: true, enumerable: true,
    get: () => SignetGlobal.createNip07Signer === createNip07Signer &&
      SignetGlobal.createLoginAuthEvent === createLoginAuthEvent &&
      SignetGlobal.createSessionFromSigner === createSessionFromSigner ? 1 : undefined,
    // The IIFE footer assigns all ESM exports additively. Its marker write is
    // not authority; the getter checks the actual current function bindings.
    set: () => {},
  });
  (window as unknown as { Signet: Record<string, unknown> }).Signet = SignetGlobal;
}
