/**
 * Amber (NIP-55) sign-in flow.
 *
 * NIP-55 is Android-only: web pages open `nostrsigner:` URLs which the
 * Android intent system routes to a signer app (Amber, Cambium, My Signet).
 * The page navigates away during sign-in; the signer signs the event and
 * reopens the app's callback URL with the percent-encoded signed event
 * appended to it, so the callback ends in `event=` and the answer arrives
 * as that parameter.
 *
 * v1 scope: sign-in only. Each kind-21236 auth event takes one round-trip
 * through Amber. Subsequent event signing during the session is not
 * supported in v1 — every sign would require another `nostrsigner:` round
 * trip, which is awful in-flow UX. Amber sessions surface as auth-only via
 * `EphemeralSigner`, mirroring the same-tab Signet redirect flow.
 *
 * NEEDS-ANDROID-VERIFICATION: this code is unverifiable from a desktop dev
 * environment. Smoke test on a real Android device with Amber installed
 * before promoting to production.
 */
import type {
  PendingRedirect,
  SignetStorage,
  SignetAuthEvent,
  SignetSession,
} from './types.js';
import { PENDING_REDIRECT_TTL_MS } from './types.js';
import {
  clearPendingRedirect,
  clearPendingRedirectFromStorage,
  loadPendingRedirect,
  loadPendingRedirectFromStorage,
  savePendingRedirectToStorage,
} from './storage.js';
import { EphemeralSigner } from './signers.js';
import { validateLoginAuthEvent } from './verify.js';

/** True when running on a likely-Android browser. Lets the picker hide the
 *  Amber option on iOS/desktop where the `nostrsigner:` scheme is unhandled. */
export function isAndroid(): boolean {
  if (typeof navigator === 'undefined') return false;
  return /android/i.test(navigator.userAgent);
}

const HEX_64 = /^[0-9a-f]{64}$/i;

export interface AmberStartOptions {
  appName: string;
  challenge: string;
  origin: string;
  /**
   * The page the signer reopens with its answer. Defaults to the origin's root.
   * The result parameters are added here; a fragment is dropped, because the
   * signer appends its result to the very end of the URL.
   */
  redirectCallback?: string;
  storage?: SignetStorage;
}

/**
 * Build the unsigned kind-21236 auth event template Amber will sign. The
 * shape mirrors what every other path produces, so server-side verification
 * is uniform regardless of which signer the user picked.
 */
function buildAuthEventTemplate(opts: AmberStartOptions): {
  kind: number;
  content: string;
  created_at: number;
  tags: string[][];
} {
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
export function amberCallbackUrl(page: string): string {
  const hash = page.indexOf('#');
  const base = (hash >= 0 ? page.slice(0, hash) : page).replace(/[?&]+$/, '');
  return `${base}${base.includes('?') ? '&' : '?'}signet_amber=1&event=`;
}

export function buildAmberSignerUrl(opts: AmberStartOptions): string {
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
export async function startAmberSignIn(opts: AmberStartOptions): Promise<never> {
  if (typeof window === 'undefined') {
    throw new Error('signet-login: amber mode requires a browser environment');
  }
  const pending: PendingRedirect = {
    challenge: opts.challenge,
    origin: opts.origin,
    appName: opts.appName,
    createdAt: Date.now(),
  };
  await savePendingRedirectToStorage(pending, opts.storage);
  window.location.href = buildAmberSignerUrl(opts);
  return new Promise<never>(() => { /* never resolves */ });
}

function cleanupAmberCallbackUrl(): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  let touched = false;
  for (const key of ['event', 'signet_amber', 'error']) {
    if (url.searchParams.has(key)) {
      url.searchParams.delete(key);
      touched = true;
    }
  }
  if (!touched) return;
  const newHref = url.pathname + (url.search ? url.search : '') + url.hash;
  try {
    window.history.replaceState(window.history.state, document.title, newHref);
  } catch {
    // history API blocked — leave URL alone
  }
}

export type ConsumeAmberResult =
  | { kind: 'session'; session: SignetSession }
  | { kind: 'denied' }
  | { kind: 'no-callback' }
  | { kind: 'invalid'; reason: string };

type ConsumeAmberFinalizer = <T extends ConsumeAmberResult>(result: T) => T | Promise<T>;

/**
 * Consume an Amber callback. Detects `?event=<base64-or-json>` (or the
 * `signet_amber=1` flag) on the URL and reconstructs a session. Idempotent:
 * a second call after a successful consume returns 'no-callback' because
 * the params have been stripped.
 */
function consumeAmberCallbackWithPending(
  pending: PendingRedirect | null,
  finalize: ConsumeAmberFinalizer,
): ConsumeAmberResult | Promise<ConsumeAmberResult> {
  if (typeof window === 'undefined') return { kind: 'no-callback' };

  const params = new URLSearchParams(window.location.search);
  const flagged = params.has('signet_amber') || params.has('event');
  if (!flagged) return { kind: 'no-callback' };

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

  // With compressionType=none signers return the signed event as JSON. Older
  // requests asked for base64 and some signers still answer that way, so a
  // reply that is not JSON is tried as base64 before it is refused.
  let parsed: unknown;
  try {
    let json = eventRaw.trim();
    if (!json.startsWith('{')) {
      json = typeof atob === 'function'
        ? atob(json)
        : Buffer.from(json, 'base64').toString('utf-8');
    }
    parsed = JSON.parse(json);
  } catch {
    return finalize({ kind: 'invalid', reason: 'event-malformed' });
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return finalize({ kind: 'invalid', reason: 'event-not-object' });
  }
  const ev = parsed as Partial<SignetAuthEvent>;
  if (
    typeof ev.id !== 'string' || !HEX_64.test(ev.id) ||
    typeof ev.pubkey !== 'string' || !HEX_64.test(ev.pubkey) ||
    typeof ev.sig !== 'string' || !/^[0-9a-f]{128}$/i.test(ev.sig) ||
    typeof ev.created_at !== 'number' ||
    !Array.isArray(ev.tags) ||
    ev.kind !== 21236 ||
    typeof ev.content !== 'string'
  ) {
    return finalize({ kind: 'invalid', reason: 'event-shape-invalid' });
  }

  const challengeTag = ev.tags.find(t => Array.isArray(t) && t[0] === 'challenge');
  if (!challengeTag || challengeTag[1] !== pending.challenge) {
    return finalize({ kind: 'invalid', reason: 'challenge-mismatch' });
  }

  const authEvent: SignetAuthEvent = {
    id: ev.id.toLowerCase(),
    pubkey: ev.pubkey.toLowerCase(),
    kind: 21236,
    created_at: ev.created_at,
    tags: ev.tags as string[][],
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
  const session: SignetSession = {
    pubkey: authEvent.pubkey,
    method: 'amber',
    signer: ephemeral,
    authEvent,
  };

  return finalize({ kind: 'session', session });
}

export function consumeAmberCallback(): ConsumeAmberResult {
  const finalize = <T extends ConsumeAmberResult>(result: T): T => {
    clearPendingRedirect();
    cleanupAmberCallbackUrl();
    return result;
  };
  return consumeAmberCallbackWithPending(loadPendingRedirect(), finalize) as ConsumeAmberResult;
}

export async function consumeAmberCallbackFromStorage(storage?: SignetStorage): Promise<ConsumeAmberResult> {
  const pending = await loadPendingRedirectFromStorage(storage);
  const finalize = async <T extends ConsumeAmberResult>(result: T): Promise<T> => {
    await clearPendingRedirectFromStorage(storage, pending);
    cleanupAmberCallbackUrl();
    return result;
  };
  return await consumeAmberCallbackWithPending(pending, finalize);
}
