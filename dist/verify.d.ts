/**
 * Server-side verifier for Signet auth events.
 *
 * Run on your server when the client posts a SignetAuthEvent — this verifies
 * the schnorr signature, the canonical event ID, and the embedded challenge /
 * origin / app tags. Pure Node-friendly: no DOM, no relays, no fetch.
 *
 *   import { verifyLogin } from 'signet-login/verify';
 *   const result = verifyLogin(authEvent, {
 *     expectedChallenge: '...',
 *     expectedOrigin: 'https://mygame.com',
 *     expectedAppName: 'Asteroid Sats',
 *   });
 */
export interface VerifyLoginOptions {
    /** The challenge the consumer issued. 64 hex. */
    expectedChallenge: string;
    /** The origin the auth event must be bound to (e.g. 'https://mygame.com'). */
    expectedOrigin: string;
    /**
     * Optional: the app name the consumer claimed at login time. If supplied,
     * the auth event's `app` tag must match.
     */
    expectedAppName?: string;
    /** Maximum age of the auth event in seconds. Default: 300 (5 min). */
    maxAgeSeconds?: number;
    /** Override Date.now() for testing. */
    now?: () => number;
}
export type VerifyLoginResult = {
    valid: true;
    pubkey: string;
    createdAt: number;
} | {
    valid: false;
    error: VerifyLoginError;
};
export type VerifyLoginError = 'malformed-event' | 'wrong-kind' | 'invalid-event-id' | 'invalid-signature' | 'challenge-mismatch' | 'origin-mismatch' | 'app-mismatch' | 'too-old' | 'in-the-future';
/**
 * Verify a Signet kind-21236 auth event against the expected challenge, origin,
 * and (optionally) app name.
 */
export declare function verifyLogin(event: unknown, opts: VerifyLoginOptions): VerifyLoginResult;
