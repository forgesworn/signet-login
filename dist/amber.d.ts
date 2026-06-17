/**
 * Amber (NIP-55) sign-in flow.
 *
 * NIP-55 is Android-only: web pages open `nostrsigner:` URLs which the
 * Android intent system routes to Amber (or any compatible signer). The
 * page navigates away during sign-in; Amber signs the event and redirects
 * the browser back to the app's callback URL with the signed event encoded
 * in a `event=` parameter.
 *
 * v1 scope: sign-in only. Each kind-21236 auth event takes one round-trip
 * through Amber. Subsequent event signing during the session is not
 * supported in v1 — every sign would require another `nostrsigner:` round
 * trip, which is awful in-flow UX. Amber sessions surface as auth-only via
 * `EphemeralSigner`, mirroring the same-tab Signet redirect flow.
 *
 * NEEDS-ANDROID-VERIFICATION: this code is unverifiable from a desktop dev
 * environment. Smoke test on a real Android device with Amber installed
 * before promoting to production.
 */
import type { SignetStorage, SignetSession } from './types.js';
/** True when running on a likely-Android browser. Lets the picker hide the
 *  Amber option on iOS/desktop where the `nostrsigner:` scheme is unhandled. */
export declare function isAndroid(): boolean;
export interface AmberStartOptions {
    appName: string;
    challenge: string;
    origin: string;
    /** Optional override for the callback URL. Defaults to current page origin. */
    redirectCallback?: string;
    storage?: SignetStorage;
}
/**
 * Build the `nostrsigner:` URL that Android dispatches to Amber. The auth
 * event is base64-encoded in the path, params control return shape + the
 * callback URL the browser navigates back to.
 */
export declare function buildAmberSignerUrl(opts: AmberStartOptions): string;
/**
 * Persist pending state, navigate to Amber. Mirror of `startRedirect` but
 * the destination is a `nostrsigner:` URL handled by Amber rather than a
 * web URL handled by signet-app. The promise never resolves — the page is
 * gone before it can.
 */
export declare function startAmberSignIn(opts: AmberStartOptions): Promise<never>;
export type ConsumeAmberResult = {
    kind: 'session';
    session: SignetSession;
} | {
    kind: 'denied';
} | {
    kind: 'no-callback';
} | {
    kind: 'invalid';
    reason: string;
};
export declare function consumeAmberCallback(): ConsumeAmberResult;
export declare function consumeAmberCallbackFromStorage(storage?: SignetStorage): Promise<ConsumeAmberResult>;
