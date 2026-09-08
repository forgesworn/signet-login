/**
 * Callback-page helper.
 *
 * This is for consumers who want to support same-device redirect (signet-app
 * redirects back to their callback page after signing). The cross-device QR
 * path used by `Signet.login()` does NOT need this — it returns directly via
 * a NIP-17 gift-wrapped relay event.
 *
 * v0.1 limitation: full same-device redirect support requires reconstruction
 * of the signed kind-21236 event from URL params. signet-app's exact redirect-
 * back parameter shape will determine this implementation. Until that's pinned
 * down, this helper just relays the raw URL params back to the opener via
 * postMessage and lets the consumer decide what to do.
 */
export interface CallbackResult {
    /** Raw URL parameters from the redirect-back. */
    params: Record<string, string>;
    /** True if this page was opened as a popup (window.opener present). */
    isPopup: boolean;
    /**
     * True when the params were delivered to the opener. False when there was
     * no opener, or when no trustworthy target origin could be determined and
     * the post was withheld — see `targetOrigin`.
     */
    posted: boolean;
}
export interface HandleCallbackOptions {
    /** Close the popup after posting to the opener. Default true. */
    closeAfterPost?: boolean;
    /**
     * Target origin for the opener postMessage. Pass the opener app's origin
     * (for example `https://app.example`) — strongly recommended, since this
     * payload carries the signed-in user's auth params and, on the
     * redirect-bunker handoff, a live `bunker://…?secret=…` NIP-46 credential.
     *
     * If omitted, `handleCallback` falls back to `document.referrer`'s origin
     * when the popup was opened with a referrer (the common case for
     * `window.open`). That fallback is best-effort — `document.referrer` can be
     * stripped by referrer policy or absent — so it is NOT a substitute for
     * passing `targetOrigin` explicitly.
     *
     * When neither is available the params are NOT posted: broadcasting them to
     * `*` would hand a working signer credential to whatever opened the popup.
     * `handleCallback` returns `posted: false` in that case and the caller still
     * receives `params`, so a consumer that genuinely wants the old broadcast
     * behaviour can opt in by passing `targetOrigin: '*'` deliberately.
     */
    targetOrigin?: string;
}
/**
 * Parse the current page's URL parameters and post them to the opener (if any).
 * Optionally close the popup.
 */
export declare function handleCallback(options?: HandleCallbackOptions): CallbackResult;
