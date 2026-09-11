/**
 * Countdown arithmetic for a cross-device sign-in.
 *
 * Everything derives from `issuedAt` — when the sign-in was issued — so the
 * countdown keeps correct time across the page being backgrounded instead of
 * restarting on focus. Same discipline that fixes the relay query window.
 */
/** Unix seconds after which a response for this sign-in is no longer accepted. */
export declare function expiresAtFor(issuedAt: number): number;
/** Whole seconds left before expiry, clamped at 0. */
export declare function remainingSeconds(issuedAt: number, now?: number): number;
/** `M:SS`, never negative. */
export declare function formatRemaining(seconds: number): string;
