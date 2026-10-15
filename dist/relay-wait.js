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
export const MAX_AUTH_RELAYS = 3;
/** Comparison key: lowercase, one trailing slash stripped. */
function relayKey(url) {
    const lower = url.trim().toLowerCase();
    return lower.endsWith('/') ? lower.slice(0, -1) : lower;
}
/**
 * The relays an auth link carries, primary first: the primary, then the
 * remaining configured relays in order, deduplicated (case-insensitively, and
 * ignoring one trailing slash) and capped at {@link MAX_AUTH_RELAYS}. The first
 * spelling of each relay is kept. Old My Signet builds read only the first
 * `relay` parameter, so primary-first keeps them working unchanged.
 */
export function buildAuthRelayList(primary, relayUrls = []) {
    const out = [];
    const seen = new Set();
    for (const raw of [primary, ...relayUrls]) {
        const url = raw.trim();
        if (!url)
            continue;
        const key = relayKey(url);
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(url);
        if (out.length >= MAX_AUTH_RELAYS)
            break;
    }
    return out;
}
// Which error to surface when every relay failed: the one that says the most.
// `timeout` outranks the relay-specific faults because it means at least one
// relay stayed up and simply never delivered.
const FAILURE_PRIORITY = ['expired', 'timeout', 'relay-refused', 'relay-closed', 'relay-error'];
function failureRank(err) {
    const rank = FAILURE_PRIORITY.indexOf(err.code ?? err.message);
    return rank === -1 ? FAILURE_PRIORITY.length : rank;
}
function abortedError() {
    const err = new Error('aborted');
    err.code = 'aborted';
    return err;
}
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
export function waitForAuthResponseOnRelays(options, relayUrls) {
    if (relayUrls.length <= 1) {
        return waitForAuthResponse({ ...options, relayUrl: relayUrls[0] ?? '' });
    }
    const callerSignal = options.abortSignal;
    const controllers = relayUrls.map(() => new AbortController());
    const abortAll = () => { for (const c of controllers)
        c.abort(); };
    if (callerSignal?.aborted)
        abortAll();
    else
        callerSignal?.addEventListener('abort', abortAll, { once: true });
    let winner;
    let decisive; // a denial: final, whatever the other relays say
    const failures = [];
    const waits = relayUrls.map((relayUrl, i) => waitForAuthResponse({ ...options, relayUrl, abortSignal: controllers[i].signal })
        .then(result => {
        if (!winner && !decisive) {
            winner = { result };
            abortAll();
        }
    })
        .catch((err) => {
        if (winner || decisive)
            return; // an abort we caused, or a late failure
        if ((err.code ?? err.message) === 'denied') {
            decisive = err;
            abortAll();
            return;
        }
        failures.push(err);
    }));
    return Promise.all(waits).then(() => {
        callerSignal?.removeEventListener('abort', abortAll);
        if (callerSignal?.aborted && !winner)
            throw abortedError();
        if (winner)
            return winner.result;
        if (decisive)
            throw decisive;
        const best = failures.reduce((a, b) => (failureRank(b) < failureRank(a) ? b : a), failures[0]);
        throw best ?? abortedError();
    });
}
