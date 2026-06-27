/**
 * Same-tab redirect flow for "Sign in with Signet".
 *
 * Two halves:
 *
 *   1. `startRedirect()` — called from `Signet.login({ mode: 'redirect' })`.
 *      Persists pending state to localStorage, builds the signet-app auth URL
 *      WITHOUT relay/sessionPubkey (so signet-app falls into its
 *      `window.location.href = callbackUrl` path), and navigates the current
 *      tab. The caller's promise never resolves in this tab — the page is
 *      gone.
 *
 *   2. `consumeCallback()` — called from `Signet.handleCallback()` on boot.
 *      Detects auth params in `window.location.search`, validates them
 *      against the persisted pending state, reconstructs the kind-21236 auth
 *      event, persists the session via the existing storage layer, strips
 *      the auth params from the URL, and returns a `SignetSession`.
 *
 * Verification note: the reconstructed auth event has a signature that was
 * produced over the original `created_at` chosen by signet-app at sign time.
 * To rebuild the event hash exactly, signet-app must emit `t` (unix seconds)
 * alongside pubkey/signature/eventId in the redirect URL — see the
 * coordinated change in signet-protocol's `buildAuthCallbackUrl`. When `t`
 * is present, the reconstructed event passes signature verification. When
 * absent (older signet-app deployments), the SDK falls back to "now" and
 * logs a warning — server-side strict verification will fail until the
 * issuer is upgraded.
 */
import type { SignetStorage, SignetSession } from './types.js';
import { DEFAULTS } from './types.js';
/** Subset of resolved options used by the redirect path. */
export interface RedirectStartOptions {
    appName: string;
    challenge: string;
    origin: string;
    signetAppOrigin: string;
    redirectCallback?: string;
    storage?: SignetStorage;
}
export interface ConsumeCallbackOptions {
    /**
     * Older signet-app deployments returned pubkey/signature/eventId without the
     * signed event's `created_at` (`t`) value, which means the SDK cannot rebuild
     * the exact event ID and verify the signature. Default true preserves that
     * legacy behavior; set false to require cryptographic verification.
     */
    allowLegacyMissingTimestamp?: boolean;
}
/**
 * Build the signet-app auth URL for redirect mode. Deliberately omits `relay`
 * and `sessionPubkey` so signet-app's `isRelayMode` check (App.tsx) returns
 * false and the redirect path runs.
 */
export declare function buildRedirectAuthUrl(opts: RedirectStartOptions): string;
/**
 * Persist pending state and navigate. Resolves to a never-settling promise on
 * success (the page navigates before it can resolve) so callers using
 * `await Signet.login()` see consistent behaviour with the relay path.
 *
 * Throws synchronously if the environment lacks `window` — calling redirect
 * mode in non-browser code is a programming error, not something to silently
 * swallow.
 */
export declare function startRedirect(opts: RedirectStartOptions): Promise<never>;
/** Outcome of consuming a redirect callback. */
export type ConsumeCallbackResult = {
    kind: 'session';
    session: SignetSession;
    /**
     * Optional NIP-46 `bunker://...` URI shipped by signet-app for the
     * redirect-bunker auto-pair flow. When present, the SDK wrapper
     * (`handleRedirectCallback`) upgrades the session from auth-only
     * (`EphemeralSigner`) to a fully-signing `BunkerSigner` so the
     * consumer can publish events without per-event prompts. Absent on
     * older signet-app deployments — the consumer just gets the
     * existing auth-only behaviour.
     */
    bunkerUri?: string;
} | {
    kind: 'denied';
} | {
    kind: 'no-callback';
} | {
    kind: 'invalid';
    reason: string;
};
export declare function consumeCallback(options?: ConsumeCallbackOptions): ConsumeCallbackResult;
export declare function consumeCallbackFromStorage(storage?: SignetStorage, options?: ConsumeCallbackOptions): Promise<ConsumeCallbackResult>;
export { DEFAULTS };
