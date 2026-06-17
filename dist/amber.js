import { PENDING_REDIRECT_TTL_MS } from './types.js';
import { clearPendingRedirect, clearPendingRedirectFromStorage, loadPendingRedirect, loadPendingRedirectFromStorage, savePendingRedirectToStorage, } from './storage.js';
import { EphemeralSigner } from './signers.js';
/** True when running on a likely-Android browser. Lets the picker hide the
 *  Amber option on iOS/desktop where the `nostrsigner:` scheme is unhandled. */
export function isAndroid() {
    if (typeof navigator === 'undefined')
        return false;
    return /android/i.test(navigator.userAgent);
}
const HEX_64 = /^[0-9a-f]{64}$/i;
/**
 * Build the unsigned kind-21236 auth event template Amber will sign. The
 * shape mirrors what every other path produces, so server-side verification
 * is uniform regardless of which signer the user picked.
 */
function buildAuthEventTemplate(opts) {
    return {
        kind: 21236,
        content: '',
        created_at: Math.floor(Date.now() / 1000),
        tags: [
            ['challenge', opts.challenge],
            ['origin', opts.origin],
            ['app', opts.appName],
        ],
    };
}
/**
 * Build the `nostrsigner:` URL that Android dispatches to Amber. The auth
 * event is base64-encoded in the path, params control return shape + the
 * callback URL the browser navigates back to.
 */
export function buildAmberSignerUrl(opts) {
    const template = buildAuthEventTemplate(opts);
    const json = JSON.stringify(template);
    // btoa handles ASCII; the JSON above is pure ASCII (hex challenge, origin
    // URL, app name passes through if ASCII) so plain btoa is correct here.
    // For non-ASCII appName we'd need TextEncoder + base64 of bytes.
    const eventB64 = typeof btoa === 'function'
        ? btoa(json)
        : Buffer.from(json, 'utf-8').toString('base64');
    const callback = opts.redirectCallback ?? `${opts.origin}/?signet_amber=1`;
    const params = new URLSearchParams({
        type: 'sign_event',
        compressionType: 'base64',
        returnType: 'event',
        callbackUrl: callback,
    });
    return `nostrsigner:${eventB64}?${params.toString()}`;
}
/**
 * Persist pending state, navigate to Amber. Mirror of `startRedirect` but
 * the destination is a `nostrsigner:` URL handled by Amber rather than a
 * web URL handled by signet-app. The promise never resolves — the page is
 * gone before it can.
 */
export async function startAmberSignIn(opts) {
    if (typeof window === 'undefined') {
        throw new Error('signet-login: amber mode requires a browser environment');
    }
    const pending = {
        challenge: opts.challenge,
        origin: opts.origin,
        appName: opts.appName,
        createdAt: Date.now(),
    };
    await savePendingRedirectToStorage(pending, opts.storage);
    window.location.href = buildAmberSignerUrl(opts);
    return new Promise(() => { });
}
function cleanupAmberCallbackUrl() {
    if (typeof window === 'undefined')
        return;
    const url = new URL(window.location.href);
    let touched = false;
    for (const key of ['event', 'signet_amber', 'error']) {
        if (url.searchParams.has(key)) {
            url.searchParams.delete(key);
            touched = true;
        }
    }
    if (!touched)
        return;
    const newHref = url.pathname + (url.search ? url.search : '') + url.hash;
    try {
        window.history.replaceState(window.history.state, document.title, newHref);
    }
    catch {
        // history API blocked — leave URL alone
    }
}
/**
 * Consume an Amber callback. Detects `?event=<base64-or-json>` (or the
 * `signet_amber=1` flag) on the URL and reconstructs a session. Idempotent:
 * a second call after a successful consume returns 'no-callback' because
 * the params have been stripped.
 */
function consumeAmberCallbackWithPending(pending, finalize) {
    if (typeof window === 'undefined')
        return { kind: 'no-callback' };
    const params = new URLSearchParams(window.location.search);
    const flagged = params.has('signet_amber') || params.has('event');
    if (!flagged)
        return { kind: 'no-callback' };
    if (params.get('error') === 'denied') {
        return finalize({ kind: 'denied' });
    }
    if (!pending) {
        return finalize({ kind: 'invalid', reason: 'no-pending-state' });
    }
    if (pending.origin !== window.location.origin) {
        return finalize({ kind: 'invalid', reason: 'origin-mismatch' });
    }
    if (Date.now() - pending.createdAt > PENDING_REDIRECT_TTL_MS) {
        return finalize({ kind: 'invalid', reason: 'pending-stale' });
    }
    const eventRaw = params.get('event');
    if (!eventRaw) {
        return finalize({ kind: 'invalid', reason: 'no-event-param' });
    }
    // Amber returns the signed event JSON, base64-encoded by default. Try
    // base64 first; fall back to plain JSON if the consumer overrode the
    // compressionType param.
    let parsed;
    try {
        let json;
        try {
            json = typeof atob === 'function'
                ? atob(eventRaw)
                : Buffer.from(eventRaw, 'base64').toString('utf-8');
        }
        catch {
            json = eventRaw;
        }
        parsed = JSON.parse(json);
    }
    catch {
        return finalize({ kind: 'invalid', reason: 'event-malformed' });
    }
    if (typeof parsed !== 'object' || parsed === null) {
        return finalize({ kind: 'invalid', reason: 'event-not-object' });
    }
    const ev = parsed;
    if (typeof ev.id !== 'string' || !HEX_64.test(ev.id) ||
        typeof ev.pubkey !== 'string' || !HEX_64.test(ev.pubkey) ||
        typeof ev.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(ev.sig) ||
        typeof ev.created_at !== 'number' ||
        !Array.isArray(ev.tags) ||
        ev.kind !== 21236 ||
        typeof ev.content !== 'string') {
        return finalize({ kind: 'invalid', reason: 'event-shape-invalid' });
    }
    const challengeTag = ev.tags.find(t => Array.isArray(t) && t[0] === 'challenge');
    if (!challengeTag || challengeTag[1] !== pending.challenge) {
        return finalize({ kind: 'invalid', reason: 'challenge-mismatch' });
    }
    const authEvent = {
        id: ev.id.toLowerCase(),
        pubkey: ev.pubkey.toLowerCase(),
        kind: 21236,
        created_at: ev.created_at,
        tags: ev.tags,
        content: ev.content,
        sig: ev.sig.toLowerCase(),
    };
    const ephemeral = new EphemeralSigner(authEvent.pubkey, authEvent);
    const session = {
        pubkey: authEvent.pubkey,
        method: 'amber',
        signer: ephemeral,
        authEvent,
    };
    return finalize({ kind: 'session', session });
}
export function consumeAmberCallback() {
    const finalize = (result) => {
        clearPendingRedirect();
        cleanupAmberCallbackUrl();
        return result;
    };
    return consumeAmberCallbackWithPending(loadPendingRedirect(), finalize);
}
export async function consumeAmberCallbackFromStorage(storage) {
    const finalize = async (result) => {
        await clearPendingRedirectFromStorage(storage);
        cleanupAmberCallbackUrl();
        return result;
    };
    return await consumeAmberCallbackWithPending(await loadPendingRedirectFromStorage(storage), finalize);
}
