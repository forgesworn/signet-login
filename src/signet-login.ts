/**
 * Signet Login SDK — Sign in with Signet for Nostr-aware websites.
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
  SignerCapabilities,
  SignetSigner,
  SignetAuthEvent,
  SignetSession,
  LoginOptions,
  RestoreOptions,
} from './types.js';

import type {
  LoginOptions,
  RestoreOptions,
  SignetSession,
  SignetAuthEvent,
} from './types.js';
import { DEFAULTS } from './types.js';
import { showLoginModal } from './modal.js';
import { saveSession, loadSession, clearSession, bytesToHexLocal, hexToBytesLocal } from './storage.js';
import {
  hasNip07,
  createNip07Signer,
  createBunkerSigner,
  EphemeralSigner,
} from './signers.js';
import { consumeAmberCallback, type ConsumeAmberResult } from './amber.js';

import { handleCallback as handlePopupCallback } from './callback.js';
import { consumeCallback, startRedirect } from './redirect.js';
import type { ConsumeCallbackResult } from './redirect.js';
export type { CallbackResult } from './callback.js';
export type { ConsumeCallbackResult } from './redirect.js';
export type { ConsumeAmberResult } from './amber.js';
export { isAndroid } from './amber.js';

/**
 * Cap the redirect-bunker auto-pair handshake. The `bunker://` URI signet-app
 * appends is best-effort and may be unreachable on arrival — most notably when
 * it points at signet-app's own in-page NIP-46 server, which the same-tab
 * navigation back to the consumer has already torn down, so the connect can
 * never complete. Bound it so boot degrades to the ephemeral auth-only session
 * in a few seconds instead of hanging the consumer on a blank screen.
 */
const REDIRECT_BUNKER_CONNECT_TIMEOUT_MS = 8_000;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Show the login picker and resolve to a SignetSession on success, or null on
 * cancel / timeout.
 *
 * When `mode: 'redirect'` is set, the picker is skipped entirely — the current
 * tab navigates to signet-app and this promise NEVER resolves in this tab.
 * Callers should treat the returned promise as "fire and forget" in that case
 * and call `Signet.handleCallback()` on the next page load to receive the
 * session. The other login methods (NIP-07, bunker) don't use redirect at all
 * and are unaffected by this option.
 */
export async function login(opts: LoginOptions): Promise<SignetSession | null> {
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
    });
  }

  const session = await showLoginModal(opts);
  if (!session) return null;

  if (opts.persist !== false) {
    persistSession(session);
  }

  return session;
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
  const stored = loadSession();
  if (!stored) return null;

  let authEvent: SignetAuthEvent;
  try {
    authEvent = JSON.parse(stored.authEventJson);
  } catch {
    clearSession();
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
        clearSession();
        return null;
      }
      return {
        pubkey: stored.pubkey,
        method: 'nip07',
        signer,
        authEvent,
      };
    } catch {
      clearSession();
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
      clearSession();
      return null;
    }
    try {
      const sk = hexToBytesLocal(stored.bunkerClientSkHex);
      const signer = await createBunkerSigner({ uri: stored.bunkerUri, clientSecretKey: sk });
      if (signer.pubkey !== stored.pubkey) {
        console.warn('[signet-login] restore: reconnected bunker pubkey mismatch — clearing session', { connected: signer.pubkey, expected: stored.pubkey });
        await signer.close();
        clearSession();
        return null;
      }
      return {
        pubkey: stored.pubkey,
        method: 'bunker',
        signer,
        authEvent,
      };
    } catch (err) {
      // Transient reconnect failure (relay slow, signer device asleep/busy). Do
      // NOT clear the stored creds — a single hiccup must not permanently break
      // the bond and force a fresh pairing (the symptom: "the signer keeps
      // asking to authorise"). Keep them so the next restore reconnects with the
      // SAME client key, which the signer device still recognises.
      console.warn('[signet-login] restore: bunker reconnect failed — keeping creds for the next retry (NOT clearing). The signer device should still recognise us on reconnect.', err);
      return null;
    }
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
export async function handleRedirectCallback(): Promise<ConsumeCallbackResult | ConsumeAmberResult> {
  // Try Amber first — its callback shape (event= param) is disjoint from
  // signet-app's (pubkey/signature/eventId), so the order doesn't matter
  // for valid callbacks. Picking Amber first only affects the 'no-callback'
  // → 'no-callback' fall-through, where checking either side first is fine.
  const amberResult = consumeAmberCallback();
  if (amberResult.kind === 'session') {
    persistSession(amberResult.session);
    return amberResult;
  }
  if (amberResult.kind !== 'no-callback') {
    return amberResult;
  }

  const result = consumeCallback();
  if (result.kind !== 'session') return result;

  // Optional redirect-bunker upgrade. signet-app appends a `bunker://` URI
  // when its NIP-46 server is enabled and the user authorised the redirect
  // login; this lets us swap the auth-only `EphemeralSigner` for a real
  // signing `BunkerSigner` in the same round-trip. Best-effort — if the
  // bunker connect fails (relay unreachable, secret expired, signet-app
  // tab closed before the connect lands) we fall back to the plain
  // ephemeral session so the consumer at least gets identity proof.
  if (result.bunkerUri) {
    try {
      const bunkerSigner = await createBunkerSigner({
        uri: result.bunkerUri,
        timeoutMs: REDIRECT_BUNKER_CONNECT_TIMEOUT_MS,
      });
      // Sanity: the bunker we connected to must sign as the same pubkey
      // the redirect callback authenticated. A mismatch here means the
      // signet-app deployment is misconfigured (or someone tampered with
      // the URL) — drop back to ephemeral rather than silently swapping
      // identity under the consumer's feet.
      if (bunkerSigner.pubkey.toLowerCase() === result.session.pubkey.toLowerCase()) {
        const upgraded: SignetSession = {
          pubkey: result.session.pubkey,
          method: 'bunker',
          signer: bunkerSigner,
          authEvent: result.session.authEvent,
        };
        if (result.session.displayName) upgraded.displayName = result.session.displayName;
        persistSession(upgraded);
        return { kind: 'session', session: upgraded };
      }
      // Pubkey mismatch — close the wayward signer to avoid leaking the
      // relay subscription, then fall through to the ephemeral path.
      console.warn('[signet-login] redirect upgrade: bunker pubkey mismatch — staying auth-only (cannot sign)', { connected: bunkerSigner.pubkey, expected: result.session.pubkey });
      try { await bunkerSigner.close(); } catch { /* ignore */ }
    } catch (err) {
      // Connect failed — leave the ephemeral session intact.
      console.warn('[signet-login] redirect upgrade: createBunkerSigner failed — staying auth-only (no live signing). Reconnect/relay issue or signer device unreachable.', err);
    }
  } else {
    console.warn('[signet-login] redirect login carried no bunkerUri — auth-only ephemeral (cannot sign). The signer device must enable its NIP-46 server to return a bunker:// URI.');
  }

  persistSession(result.session);
  return result;
}

/**
 * Clear the stored session and close the active signer.
 */
export async function logout(currentSession?: SignetSession): Promise<void> {
  if (currentSession) {
    try { await currentSession.signer.close(); } catch { /* ignore */ }
  }
  clearSession();
}

// ── Persistence helpers (internal) ────────────────────────────────────────────

function persistSession(session: SignetSession): void {
  // nsec sessions are deliberately in-memory only — writing the pubkey or
  // even the method to storage would leak that this user has used a paste
  // path. Reload lands the user back on the picker, which is the contract
  // we surface in runNsecFlow's warning copy.
  if (session.method === 'nsec') return;

  const payload: Parameters<typeof saveSession>[0] = {
    pubkey: session.pubkey,
    method: session.method,
    authEventJson: JSON.stringify(session.authEvent),
  };

  if (session.method === 'bunker') {
    // Cast: in bunker mode, the signer is a BunkerSignerImpl with bunkerUri + clientSecretKey
    const bunkerSigner = session.signer as unknown as {
      bunkerUri?: string;
      clientSecretKey?: Uint8Array;
    };
    if (bunkerSigner.bunkerUri && bunkerSigner.clientSecretKey instanceof Uint8Array) {
      payload.bunkerUri = bunkerSigner.bunkerUri;
      payload.bunkerClientSkHex = bytesToHexLocal(bunkerSigner.clientSecretKey);
    }
  }

  if (session.expiresAt !== undefined) payload.expiresAt = session.expiresAt;
  if (session.displayName !== undefined) payload.displayName = session.displayName;

  saveSession(payload);
}

// ── Auto-attach to window.Signet (additive) ───────────────────────────────────

if (typeof window !== 'undefined') {
  // Never overwrite — additive only. Coexists with signet-verify on the same page.
  const existing = (window as unknown as { Signet?: Record<string, unknown> }).Signet;
  const SignetGlobal = existing ?? {};
  Object.assign(SignetGlobal, {
    login,
    restoreSession,
    logout,
    handleCallback,
    handleRedirectCallback,
  });
  (window as unknown as { Signet: Record<string, unknown> }).Signet = SignetGlobal;
}
