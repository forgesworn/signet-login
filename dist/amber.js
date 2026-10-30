import { PENDING_REDIRECT_TTL_MS } from './types.js';
import { clearPendingRedirect, clearPendingRedirectFromStorage, loadPendingRedirect, loadPendingRedirectFromStorage, savePendingRedirectToStorage, } from './storage.js';
import { EphemeralSigner } from './signers.js';
import { validateLoginAuthEvent } from './verify.js';
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
export function amberCallbackUrl(page) {
    const hash = page.indexOf('#');
    const base = (hash >= 0 ? page.slice(0, hash) : page).replace(/[?&]+$/, '');
    return `${base}${base.includes('?') ? '&' : '?'}signet_amber=1&event=`;
}
export function buildAmberSignerUrl(opts) {
    const template = buildAuthEventTemplate(opts);
    const json = JSON.stringify(template);
    const callback = amberCallbackUrl(opts.redirectCallback ?? `${opts.origin}/`);
    const params = new URLSearchParams({
        type: 'sign_event',
        compressionType: 'none',
        returnType: 'event',
        callbackUrl: callback,
    });
    return `nostrsigner:${encodeURIComponent(json)}?${params.toString()}`;
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
    // The answer is the flag, an error and the event value the signer appended
    // last. A page may carry an `event` parameter of its own (a stage link);
    // that one stays, and the rest keep their order.
    const entries = [...url.searchParams.entries()];
    const answer = entries.map(([key]) => key).lastIndexOf('event');
    const kept = entries.filter(([key], index) => key !== 'signet_amber' && key !== 'error' && index !== answer);
    if (kept.length === entries.length)
        return;
    url.search = new URLSearchParams(kept).toString();
    const newHref = url.pathname + (url.search ? url.search : '') + url.hash;
    try {
        window.history.replaceState(window.history.state, document.title, newHref);
    }
    catch {
        // history API blocked — leave URL alone
    }
}
/**
 * Consume a signer's callback. Detects the `signet_amber=1` flag the SDK put
 * on the callback URL and reconstructs a session from the `event=` value the
 * signer appended after it. A bare `event=` is never an answer: pages use
 * that name for their own purposes (a stage link), and reading it would strip
 * it. Idempotent: a second call after a successful consume returns
 * 'no-callback' because the answer has been stripped.
 */
function consumeAmberCallbackWithPending(pending, finalize) {
    if (typeof window === 'undefined')
        return { kind: 'no-callback' };
    const params = new URLSearchParams(window.location.search);
    if (!params.has('signet_amber'))
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
    // The signer appends its answer to the end of the callback, so it is the
    // last `event` value; an earlier one belongs to the page.
    const eventRaw = params.getAll('event').pop();
    if (!eventRaw) {
        return finalize({ kind: 'invalid', reason: 'no-event-param' });
    }
    // With compressionType=none signers return the signed event as JSON. Older
    // requests asked for base64 and some signers still answer that way, so a
    // reply that is not JSON is tried as base64 before it is refused.
    let parsed;
    try {
        let json = eventRaw.trim();
        if (!json.startsWith('{')) {
            json = typeof atob === 'function'
                ? atob(json)
                : Buffer.from(json, 'base64').toString('utf-8');
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
    const verification = validateLoginAuthEvent(authEvent, {
        expectedChallenge: pending.challenge,
        expectedOrigin: pending.origin,
        expectedAppName: pending.appName,
    });
    if (!verification.valid) {
        return finalize({ kind: 'invalid', reason: verification.error });
    }
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
    const pending = await loadPendingRedirectFromStorage(storage);
    const finalize = async (result) => {
        await clearPendingRedirectFromStorage(storage, pending);
        cleanupAmberCallbackUrl();
        return result;
    };
    return await consumeAmberCallbackWithPending(pending, finalize);
}
