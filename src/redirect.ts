/**
 * Same-tab redirect flow for "Sign in with Signet".
 *
 * Two halves:
 *
 *   1. `startRedirect()` — called from `Signet.login({ mode: 'redirect' })`.
 *      Persists pending state to localStorage, builds the signet-app auth URL
 *      WITHOUT relay/sessionPubkey (so signet-app falls into its
 *      `window.location.href = callbackUrl` path), and navigates the current
 *      tab. The caller's promise normally never resolves in this tab because
 *      the page is gone; if a browser restores the page when the user presses
 *      Back, the promise resolves null so the caller can leave its loading
 *      state.
 *
 *   2. `consumeCallback()` — called from `Signet.handleCallback()` on boot.
 *      Detects auth params in `window.location.search`, validates them
 *      against the persisted pending state, reconstructs the kind-21236 auth
 *      event, persists the session via the existing storage layer, strips
 *      the auth params from the URL, and returns a `SignetSession`.
 *
 * Verification note: the reconstructed auth event has a signature that was
 * produced over the original `created_at` chosen by signet-app at sign time.
 * To rebuild the event hash exactly, signet-app must emit `t` (unix seconds)
 * alongside pubkey/signature/eventId in the redirect URL — see the
 * coordinated change in signet-protocol's `buildAuthCallbackUrl`. When `t`
 * is present, the reconstructed event passes signature verification. When
 * absent (older signet-app deployments), the SDK falls back to "now" and
 * logs a warning — server-side strict verification will fail until the
 * issuer is upgraded.
 */

import type {
  PendingRedirect,
  SignetStorage,
  SignetAuthEvent,
  SignetSession,
} from './types.js';
import { DEFAULTS, PENDING_REDIRECT_TTL_MS } from './types.js';
import {
  clearPendingRedirect,
  clearPendingRedirectFromStorage,
  loadPendingRedirect,
  loadPendingRedirectFromStorage,
  savePendingRedirectToStorage,
} from './storage.js';
import { EphemeralSigner } from './signers.js';
import { validateLoginAuthEvent } from './verify.js';

/** Subset of resolved options used by the redirect path. */
export interface RedirectStartOptions {
  appName: string;
  challenge: string;
  origin: string;
  signetAppOrigin: string;
  redirectCallback?: string;
  storage?: SignetStorage;
}

export interface ConsumeCallbackOptions {
  /**
   * Older signet-app deployments returned pubkey/signature/eventId without the
   * signed event's `created_at` (`t`) value, which means the SDK cannot rebuild
   * the exact event ID and CANNOT verify the signature — a missing `t` is
   * cryptographically unverifiable, not just legacy. Secure by default: a
   * callback missing `t` is rejected (`reason: 't-required'`) unless you set
   * this to `true` explicitly. Only opt in if you control the signet-app
   * deployment on the other end and accept that the resulting session's
   * pubkey is UNVERIFIED — an attacker who can reach your callback URL can
   * inject an arbitrary `pubkey` as an authenticated session when this is on.
   */
  allowLegacyMissingTimestamp?: boolean;
}

/** Hex regexes — kept local to avoid pulling in @noble for two patterns. */
const HEX_64 = /^[0-9a-f]{64}$/i;
const HEX_128 = /^[0-9a-f]{128}$/i;

/** Length cap for the unsigned `display_name` redirect param. */
const MAX_DISPLAY_NAME_LENGTH = 128;

/**
 * Build the signet-app auth URL for redirect mode. Deliberately omits `relay`
 * and `sessionPubkey` so signet-app's `isRelayMode` check (App.tsx) returns
 * false and the redirect path runs.
 */
export function buildRedirectAuthUrl(opts: RedirectStartOptions): string {
  const callback = opts.redirectCallback ?? `${opts.origin}/`;
  const params = new URLSearchParams({
    auth: '1',
    challenge: opts.challenge,
    origin: opts.origin,
    name: opts.appName,
    callback,
    t: String(Math.floor(Date.now() / 1000)),
  });
  return `${opts.signetAppOrigin}/?${params.toString()}`;
}

/**
 * Persist pending state and navigate. Normally the page navigates before this
 * promise can resolve. If the user backs out and the browser restores this page
 * from the back/forward cache, resolve null and clear pending redirect state so
 * the caller does not stay stuck awaiting a login that was abandoned.
 *
 * Throws synchronously if the environment lacks `window` — calling redirect
 * mode in non-browser code is a programming error, not something to silently
 * swallow.
 */
export async function startRedirect(opts: RedirectStartOptions): Promise<null> {
  if (typeof window === 'undefined') {
    throw new Error('signet-login: redirect mode requires a browser environment');
  }
  const pending: PendingRedirect = {
    challenge: opts.challenge,
    origin: opts.origin,
    appName: opts.appName,
    createdAt: Date.now(),
  };
  await savePendingRedirectToStorage(pending, opts.storage);
  const url = buildRedirectAuthUrl(opts);
  const cancelledByBack = new Promise<null>(resolve => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('pageshow', onPageShow);
      void clearPendingRedirectFromStorage(opts.storage).finally(() => resolve(null));
    };
    const onPageShow = (event: PageTransitionEvent): void => {
      if (event.persisted) finish();
    };
    window.addEventListener('pageshow', onPageShow);
  });
  // Use assignment (not replace) so the user can hit back to abort. The
  // pending record stays put unless this same JS context is restored from BFCache;
  // a fresh reload can still overwrite it on the next login attempt.
  window.location.href = url;
  return cancelledByBack;
}

/**
 * Strip auth-callback params from the current URL via `history.replaceState`,
 * preserving anything else the consumer has on the URL. No-op when there's
 * no auth-callback param present.
 */
function cleanupCallbackUrl(): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  const removed = ['pubkey', 'npub', 'signature', 'eventId', 'error', 'warnings', 'fromNP', 'display_name', 't', 'bunker', 'avatar_hash', 'avatar_url', 'avatar_key'];
  let touched = false;
  for (const key of removed) {
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
    // history API blocked (file:// origin, sandboxed iframe, …) — leave URL alone
  }
}

/** Outcome of consuming a redirect callback. */
export type ConsumeCallbackResult =
  | {
      kind: 'session';
      session: SignetSession;
      /**
       * Optional NIP-46 `bunker://...` URI shipped by signet-app for the
       * redirect-bunker auto-pair flow. When present, the SDK wrapper
       * (`handleRedirectCallback`) upgrades the session from auth-only
       * (`EphemeralSigner`) to a fully-signing `BunkerSigner` so the
       * consumer can publish events without per-event prompts. Absent on
       * older signet-app deployments — the consumer just gets the
       * existing auth-only behaviour.
       */
      bunkerUri?: string;
    }
  | { kind: 'denied' }
  | { kind: 'no-callback' }
  | { kind: 'invalid'; reason: string };

/**
 * Detect and consume a redirect-back callback. Returns:
 *
 *   - { kind: 'session', session }  — round-trip valid; clears pending state
 *                                     and strips auth params from the URL
 *   - { kind: 'denied' }            — signet-app sent `error=denied`
 *   - { kind: 'no-callback' }       — no auth params in the URL; do nothing
 *   - { kind: 'invalid', reason }   — params present but failed validation
 *                                     (pending state mismatch, stale, hex
 *                                     malformed, …). Pending state is cleared
 *                                     in this case too — a stale or attacker-
 *                                     supplied URL shouldn't poison the next
 *                                     login attempt.
 *
 * Idempotent: calling it twice on the same loaded page returns 'no-callback'
 * the second time because the URL params have been stripped.
 */
type ConsumeCallbackFinalizer = <T extends ConsumeCallbackResult>(result: T) => T | Promise<T>;

function consumeCallbackWithPending(
  pending: PendingRedirect | null,
  finalize: ConsumeCallbackFinalizer,
  options: ConsumeCallbackOptions = {},
): ConsumeCallbackResult | Promise<ConsumeCallbackResult> {
  if (typeof window === 'undefined') return { kind: 'no-callback' };

  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  const pubkey = params.get('pubkey');
  const signature = params.get('signature');
  const eventId = params.get('eventId');

  // No callback at all — early return without touching pending state.
  if (!error && !pubkey && !signature && !eventId) {
    return { kind: 'no-callback' };
  }

  if (error === 'denied') {
    return finalize({ kind: 'denied' });
  }

  if (!pending) {
    return finalize({ kind: 'invalid', reason: 'no-pending-state' });
  }

  // Origin sanity — protects against a callback URL fired at a different app
  // (e.g. attacker emails a crafted link). Pending was issued by `origin`
  // matching the calling page; on return the page must still be on that origin.
  if (pending.origin !== window.location.origin) {
    return finalize({ kind: 'invalid', reason: 'origin-mismatch' });
  }

  // Freshness — a callback hours after the user clicked Sign In is almost
  // certainly a stale tab restore. Reject rather than reconstructing an
  // expired auth event.
  if (Date.now() - pending.createdAt > PENDING_REDIRECT_TTL_MS) {
    return finalize({ kind: 'invalid', reason: 'pending-stale' });
  }

  if (!pubkey || !HEX_64.test(pubkey)) {
    return finalize({ kind: 'invalid', reason: 'pubkey-malformed' });
  }
  if (!signature || !HEX_128.test(signature)) {
    return finalize({ kind: 'invalid', reason: 'signature-malformed' });
  }
  if (!eventId || !HEX_64.test(eventId)) {
    return finalize({ kind: 'invalid', reason: 'eventId-malformed' });
  }

  // `t` (created_at unix seconds) — emitted by signet-app for exact event
  // reconstruction. Fall back to "now" with a warning when absent (older
  // signet-app deployments). See module-level note.
  let createdAt: number;
  let legacyUnverifiedTimestamp = false;
  const tRaw = params.get('t');
  if (tRaw && /^\d+$/.test(tRaw)) {
    const t = Number(tRaw);
    if (!Number.isFinite(t)) return finalize({ kind: 'invalid', reason: 't-malformed' });
    createdAt = t;
  } else if (options.allowLegacyMissingTimestamp !== true) {
    // Secure by default: without `t` the SDK cannot rebuild the signed event
    // ID, so the signature can never be checked and `pubkey` is effectively
    // attacker-controlled. Reject unless the consumer has explicitly opted
    // into the unverified legacy path.
    return finalize({ kind: 'invalid', reason: 't-required' });
  } else {
    createdAt = Math.floor(Date.now() / 1000);
    legacyUnverifiedTimestamp = true;
    // Surface this in dev tools so consumers can spot upstream signet-app
    // versions that don't emit `t`. Doesn't fail the flow because the
    // consumer has explicitly opted into the unverified session; only
    // strict server-side verification will reject it.
    if (typeof console !== 'undefined') {
      console.warn(
        'signet-login: redirect callback missing `t` param — auth event ' +
        'created_at approximated and the redirect signature CANNOT be ' +
        'verified client-side, so `pubkey` is unverified. This path only ' +
        'ran because allowLegacyRedirectWithoutTimestamp was explicitly ' +
        'set to true. Upgrade signet-app to emit `t` in the redirect URL ' +
        'and remove that option as soon as possible.',
      );
    }
  }

  const lowerPubkey = pubkey.toLowerCase();
  const lowerSig = signature.toLowerCase();
  const lowerEventId = eventId.toLowerCase();

  // Reconstruct the tag list signet-app *actually signed with*. Looking at
  // signet-app/src/lib/signet.ts::signAuthChallenge, the kind-21236 event
  // carries `[challenge, origin]` plus optional avatar metadata. Notably it
  // does NOT include an `app` tag (yet). Including extra tags here breaks
  // the event-ID hash check on any strict server-side verifier — they hash
  // a tuple that includes our reconstruction but the signature was
  // generated over a different tuple.
  //
  // Avatar params arrive on the redirect URL when the persona has an
  // avatar set (see signet-app/src/lib/url-auth.ts::appendUrlAuthExtras).
  // Pull them in the same order signet-app emits them so the canonical
  // serialisation matches what was signed.
  const tags: string[][] = [
    ['challenge', pending.challenge],
    ['origin', pending.origin],
  ];
  const avatarHash = params.get('avatar_hash');
  const avatarUrl = params.get('avatar_url');
  const avatarKey = params.get('avatar_key');
  if (avatarHash && /^[0-9a-f]{64}$/i.test(avatarHash)) tags.push(['avatar_hash', avatarHash]);
  if (avatarUrl && avatarUrl.length <= 500) tags.push(['avatar_url', avatarUrl]);
  if (avatarKey && /^[0-9a-f]{64}$/i.test(avatarKey)) tags.push(['avatar_key', avatarKey]);

  const authEvent: SignetAuthEvent = {
    id: lowerEventId,
    pubkey: lowerPubkey,
    kind: 21236,
    created_at: createdAt,
    tags,
    content: '',
    sig: lowerSig,
  };

  if (!legacyUnverifiedTimestamp) {
    const verification = validateLoginAuthEvent(authEvent, {
      expectedChallenge: pending.challenge,
      expectedOrigin: pending.origin,
    });
    if (!verification.valid) {
      return finalize({ kind: 'invalid', reason: verification.error });
    }
  }

  // `display_name` is outside the signature — signet-app appends it to the
  // redirect URL but it is not one of the tags the event ID covers, so unlike
  // `pubkey`/`sig`/`eventId` nothing here can attest to it. Cap it so a
  // consumer that renders the session's display name is not handed unbounded
  // attacker-shaped text from a URL parameter. Consumers must still treat it
  // as untrusted and escape it.
  const displayNameRaw = params.get('display_name');
  const displayName = displayNameRaw && displayNameRaw.length <= MAX_DISPLAY_NAME_LENGTH
    ? displayNameRaw
    : undefined;
  const ephemeral = new EphemeralSigner(lowerPubkey, authEvent);
  const session: SignetSession = {
    pubkey: lowerPubkey,
    method: 'redirect',
    signer: ephemeral,
    authEvent,
  };
  if (displayName) session.displayName = displayName;

  // Optional bunker URI for the redirect-bunker auto-pair flow. We just
  // shuttle the string here — the async upgrade to a `BunkerSigner` happens
  // in `handleRedirectCallback`, which is already async. Light shape check
  // (must start `bunker://`, length-cap) so a malformed param doesn't
  // travel further into the SDK; deeper validation lives in
  // `createBunkerSigner` / `parsePairingURI`.
  const bunkerRaw = params.get('bunker');
  let bunkerUri: string | undefined;
  if (bunkerRaw && bunkerRaw.length >= 9 && bunkerRaw.length <= 8192
      && bunkerRaw.slice(0, 9).toLowerCase() === 'bunker://') {
    bunkerUri = bunkerRaw;
  }

  return finalize(bunkerUri ? { kind: 'session', session, bunkerUri } : { kind: 'session', session });
}

export function consumeCallback(options: ConsumeCallbackOptions = {}): ConsumeCallbackResult {
  // From here on we're handling a callback — pending state must always be
  // cleared on exit so a stale record can't be reused.
  const finalize = <T extends ConsumeCallbackResult>(result: T): T => {
    clearPendingRedirect();
    cleanupCallbackUrl();
    return result;
  };
  return consumeCallbackWithPending(loadPendingRedirect(), finalize, options) as ConsumeCallbackResult;
}

export async function consumeCallbackFromStorage(
  storage?: SignetStorage,
  options: ConsumeCallbackOptions = {},
): Promise<ConsumeCallbackResult> {
  const finalize = async <T extends ConsumeCallbackResult>(result: T): Promise<T> => {
    await clearPendingRedirectFromStorage(storage);
    cleanupCallbackUrl();
    return result;
  };
  return await consumeCallbackWithPending(await loadPendingRedirectFromStorage(storage), finalize, options);
}

// Re-export DEFAULTS for tree-shaking-friendly callers that want to avoid
// importing the full types module just for one constant.
export { DEFAULTS };
