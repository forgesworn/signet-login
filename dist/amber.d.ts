/**
 * Amber (NIP-55) sign-in flow.
 *
 * NIP-55 is Android-only: web pages open `nostrsigner:` URLs which the
 * Android intent system routes to a signer app (Amber, Cambium, My Signet).
 * The page navigates away during sign-in; the signer signs the event and
 * reopens the app's callback URL with the percent-encoded signed event
 * appended to it, so the callback ends in `event=` and the answer arrives
 * as that parameter.
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
    /**
     * The page the signer reopens with its answer. Defaults to the origin's root.
     * The result parameters are added here; a fragment is dropped, because the
     * signer appends its result to the very end of the URL.
     */
    redirectCallback?: string;
    storage?: SignetStorage;
}
/**
 * Build the `nostrsigner:` URL that Android dispatches to a NIP-55 signer
 * (Amber, Cambium, My Signet). NIP-55's web form: the event JSON, URL-encoded,
 * in the path, and `compressionType` none or gzip for the reply. The earlier
 * `compressionType=base64` with a base64 path is not in NIP-55, so strict
 * signers (Cambium) refused it as an invalid request.
 */
/**
 * The callback a NIP-55 signer answers to. Signers append the percent-encoded
 * result to the end of the URL (NIP-55's example ends in `?event=`; Amber does
 * `callBackUrl + Uri.encode(value)`, Cambium `callback + percentEncode(value)`),
 * so the URL must end in `event=` for `consumeAmberCallback` to find the event.
 * The former `?signet_amber=1` callback made the event the tail of that flag's
 * value, and no signer's answer ever signed anyone in.
 */
export declare function amberCallbackUrl(page: string): string;
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
