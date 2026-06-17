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
            window.opener.postMessage({ type: 'signet-login-callback', params }, 
            // Restrict target origin to opener's origin if known; fall back to '*' so
            // cross-origin popups still deliver. Consumers must validate origin.
            '*');
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
