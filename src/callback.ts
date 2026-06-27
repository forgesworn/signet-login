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
}

export interface HandleCallbackOptions {
  /** Close the popup after posting to the opener. Default true. */
  closeAfterPost?: boolean;
  /**
   * Target origin for the opener postMessage. Pass the opener app's origin
   * (for example `https://app.example`) to avoid leaking auth params to an
   * unexpected opener. Defaults to `*` for backwards compatibility.
   */
  targetOrigin?: string;
}

/**
 * Parse the current page's URL parameters and post them to the opener (if any).
 * Optionally close the popup.
 */
export function handleCallback(options?: HandleCallbackOptions): CallbackResult {
  const params: Record<string, string> = {};
  if (typeof window !== 'undefined') {
    const search = new URLSearchParams(window.location.search);
    search.forEach((value, key) => {
      params[key] = value;
    });
  }

  const isPopup = typeof window !== 'undefined' && !!window.opener && window.opener !== window;

  if (isPopup) {
    try {
      window.opener.postMessage(
        { type: 'signet-login-callback', params },
        options?.targetOrigin ?? '*',
      );
    } catch {
      // postMessage failed — ignore
    }
    if (options?.closeAfterPost ?? true) {
      try { window.close(); } catch { /* ignore */ }
    }
  }

  return { params, isPopup };
}
