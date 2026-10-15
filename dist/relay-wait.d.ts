/**
 * Multi-relay helpers for the Signet redirect / QR sign-in flow
 * (`remote-signet` and `local-signet`).
 *
 * The `?auth=1` link names the relays My Signet may publish the response to,
 * and this module's `waitForAuthResponseOnRelays` listens on every one of them.
 * A single unreachable relay (the phone cannot reach it, or it refuses
 * kind-1059 reads) then no longer sinks an otherwise working sign-in.
 */
import { waitForAuthResponse } from 'signet-verify';
/** Most relays the auth link carries and the flow listens on. */
export declare const MAX_AUTH_RELAYS = 3;
/**
 * The relays an auth link carries, primary first: the primary, then the
 * remaining configured relays in order, deduplicated (case-insensitively, and
 * ignoring one trailing slash) and capped at {@link MAX_AUTH_RELAYS}. The first
 * spelling of each relay is kept. Old My Signet builds read only the first
 * `relay` parameter, so primary-first keeps them working unchanged.
 */
export declare function buildAuthRelayList(primary: string, relayUrls?: readonly string[]): string[];
type WaitOptions = Parameters<typeof waitForAuthResponse>[0];
type WaitResult = Awaited<ReturnType<typeof waitForAuthResponse>>;
/**
 * `waitForAuthResponse` across several relays. One call per relay; the first
 * valid approval wins and every other subscription is aborted (so a duplicate
 * of the same response arriving later is never processed). A denial on any
 * relay is final. A relay failing (error, close, refusal, timeout) only fails
 * the wait once EVERY relay has failed, so one dead relay cannot hide an
 * approval delivered on another. The returned promise settles only after every
 * underlying wait has joined, so the caller may zero `sessionPrivKey` as soon
 * as it settles. Each wait validates the response exactly as before.
 *
 * With one relay this is `waitForAuthResponse` itself, untouched.
 */
export declare function waitForAuthResponseOnRelays(options: Omit<WaitOptions, 'relayUrl'>, relayUrls: readonly string[]): Promise<WaitResult>;
export {};
