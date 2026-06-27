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
export type { NostrEvent, EventTemplate, LoginMethod, LoginPickerMethod, SignerCapabilities, SignetSigner, SignetAuthEvent, SignetSession, NostrConnectStatus, NostrConnectStatusHandler, NostrConnectStatusPhase, NostrConnectStatusType, LoginOptions, RestoreOptions, SignetStorage, } from './types.js';
import type { SignetSigner, LoginOptions, RestoreOptions, SignetSession, SignetAuthEvent, SignetStorage } from './types.js';
import { hasNip07, createNip07Signer, createBunkerSigner, createBunkerSignerFromNostrConnect, buildNostrConnectUri, buildBunkerUriFromNostrConnectUri, isBunkerUri, isNostrConnectUri, isSupportedPairingUri, createLocalSignerFromNsec, generateSecretKey, Nip07Signer, BunkerSignerImpl, LocalSigner } from './signers.js';
import { type ConsumeAmberResult } from './amber.js';
import { handleCallback as handlePopupCallback } from './callback.js';
import type { ConsumeCallbackResult } from './redirect.js';
export type { CallbackResult, HandleCallbackOptions } from './callback.js';
export type { ConsumeCallbackResult } from './redirect.js';
export type { ConsumeAmberResult } from './amber.js';
export { isAndroid } from './amber.js';
export { hasNip07, createNip07Signer, createBunkerSigner, createBunkerSignerFromNostrConnect, buildNostrConnectUri, buildBunkerUriFromNostrConnectUri, isBunkerUri, isNostrConnectUri, isSupportedPairingUri, createLocalSignerFromNsec, generateSecretKey, Nip07Signer, BunkerSignerImpl, LocalSigner, };
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
     * which prevents client-side signature verification. Default true preserves
     * those existing integrations; set false to reject unverifiable callbacks.
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
export declare function login(opts: LoginOptions): Promise<SignetSession | null>;
/**
 * Headless helper for custom UIs. Given any SignetSigner, sign the same
 * kind-21236 login proof the built-in picker uses.
 */
export declare function createLoginAuthEvent(signer: SignetSigner, opts: CreateLoginAuthEventOptions): Promise<SignetAuthEvent>;
/**
 * Headless helper for custom UIs. Builds the same SignetSession shape returned
 * by `login()` from a signer the caller already obtained.
 */
export declare function createSessionFromSigner(signer: SignetSigner, opts: CreateLoginAuthEventOptions): Promise<SignetSession>;
/**
 * Try to restore a session from localStorage. Returns null if no session is
 * stored or it's malformed/expired.
 *
 * For bunker sessions, attempts to reconnect using the stored URI + client SK.
 * If the bunker is unreachable, returns null and clears the stored session.
 */
export declare function restoreSession(opts?: RestoreOptions): Promise<SignetSession | null>;
/**
 * Popup-style callback receiver. Use on the page that signet-app redirects
 * a popup to. Parses URL params and posts them to `window.opener`, then
 * closes the popup. Returns the raw params for non-popup contexts.
 *
 * For the same-tab redirect flow (`mode: 'redirect'` on `login()`), use
 * `Signet.handleRedirectCallback()` instead — that one validates against the
 * persisted pending state and returns a fully-formed `SignetSession`.
 */
export declare const handleCallback: typeof handlePopupCallback;
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
export declare function handleRedirectCallback(options?: HandleRedirectCallbackOptions): Promise<ConsumeCallbackResult | ConsumeAmberResult>;
/**
 * Clear the stored session and close the active signer.
 */
export declare function logout(currentSession?: SignetSession, opts?: LogoutOptions): Promise<void>;
