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
/**
 * Best-effort safe target origin when the caller didn't pass one explicitly:
 * derive it from `document.referrer`, which the browser sets to the opener's
 * URL for a same-tab `window.open()` popup (absent `noreferrer`/strict
 * Referrer-Policy). Returns `null` when no origin can be derived, in which
 * case the caller falls back to `'*'`.
 */
function deriveOpenerOrigin() {
    if (typeof document === 'undefined' || !document.referrer)
        return null;
    try {
        return new URL(document.referrer).origin;
    }
    catch {
        return null;
    }
}
/**
 * Parse the current page's URL parameters and post them to the opener (if any).
 * Optionally close the popup.
 */
export function handleCallback(options) {
    const params = {};
    if (typeof window !== 'undefined') {
        const search = new URLSearchParams(window.location.search);
        search.forEach((value, key) => {
            params[key] = value;
        });
    }
    const isPopup = typeof window !== 'undefined' && !!window.opener && window.opener !== window;
    if (isPopup) {
        try {
            window.opener.postMessage({ type: 'signet-login-callback', params }, options?.targetOrigin ?? deriveOpenerOrigin() ?? '*');
        }
        catch {
            // postMessage failed — ignore
        }
        if (options?.closeAfterPost ?? true) {
            try {
                window.close();
            }
            catch { /* ignore */ }
        }
    }
    return { params, isPopup };
}
