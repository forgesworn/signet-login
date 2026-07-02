/**
 * Tests for the same-tab redirect flow.
 *
 * Covers the consumer side (consumeCallback / handleRedirectCallback): the
 * `startRedirect` half just navigates and is harder to assert in jsdom — we
 * smoke-test the URL builder instead and rely on integration testing for the
 * navigation itself.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

import {
  buildRedirectAuthUrl,
  consumeCallback,
  startRedirect,
} from '../src/redirect.js';
import {
  savePendingRedirect,
  savePendingRedirectToStorage,
  loadPendingRedirect,
  loadPendingRedirectFromStorage,
  clearPendingRedirect,
  loadSession,
  loadSessionFromStorage,
} from '../src/storage.js';
import { STORAGE_KEYS, PENDING_REDIRECT_TTL_MS, type SignetStorage } from '../src/types.js';
import { handleRedirectCallback } from '../src/signet-login.js';
import { callbackSearchForAuthEvent, makeAuthEvent } from './helpers/auth-event.js';

const ORIGIN = 'https://pallasite.example';
const APP_NAME = 'Pallasite';
const CHALLENGE = 'a'.repeat(64);
const PUBKEY = 'b'.repeat(64);
const SIGNATURE = 'c'.repeat(128);
const EVENT_ID = 'd'.repeat(64);

/**
 * Stage the URL for a test by leaning on jsdom's native location handling.
 *
 * jsdom's window.location.origin defaults to `http://localhost:3000` (the
 * default test base URL) and isn't easily retargeted via `history.*` alone.
 * Rather than fight that, we use the jsdom-native origin everywhere — the
 * SDK only cares that `pending.origin === window.location.origin`, so we
 * bind both ends of the comparison to whatever jsdom chose. `setLocation`
 * therefore only needs to set `pathname + search` via `history.replaceState`,
 * which `consumeCallback`'s own `history.replaceState` correctly updates on
 * cleanup.
 */
const JSDOM_ORIGIN = window.location.origin;

async function settleMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function dispatchPersistedPageShow(): void {
  const event = new Event('pageshow') as PageTransitionEvent;
  Object.defineProperty(event, 'persisted', { value: true });
  window.dispatchEvent(event);
}

function memoryStorage(): SignetStorage {
  const data = new Map<string, string>();
  return {
    async getItem(key: string) {
      return data.get(key) ?? null;
    },
    async setItem(key: string, value: string) {
      data.set(key, value);
    },
    async removeItem(key: string) {
      data.delete(key);
    },
  };
}

function setLocation(search: string): void {
  const fullSearch = search.startsWith('?') ? search : (search ? `?${search}` : '');
  window.history.replaceState(null, '', `/${fullSearch}`);
}

describe('buildRedirectAuthUrl', () => {
  it('builds an auth URL without relay/sessionPubkey', () => {
    const url = new URL(
      buildRedirectAuthUrl({
        appName: APP_NAME,
        challenge: CHALLENGE,
        origin: ORIGIN,
        signetAppOrigin: 'https://mysignet.app',
      }),
    );
    expect(url.searchParams.get('auth')).toBe('1');
    expect(url.searchParams.get('challenge')).toBe(CHALLENGE);
    expect(url.searchParams.get('origin')).toBe(ORIGIN);
    expect(url.searchParams.get('name')).toBe(APP_NAME);
    expect(url.searchParams.get('callback')).toBe(`${ORIGIN}/`);
    expect(url.searchParams.get('t')).toMatch(/^\d+$/);
    // Critically: NO relay or sessionPubkey — that's what tells signet-app
    // to use the redirect path instead of relay delivery.
    expect(url.searchParams.has('relay')).toBe(false);
    expect(url.searchParams.has('sessionPubkey')).toBe(false);
  });

  it('honours an explicit redirectCallback', () => {
    const url = new URL(
      buildRedirectAuthUrl({
        appName: APP_NAME,
        challenge: CHALLENGE,
        origin: ORIGIN,
        signetAppOrigin: 'https://mysignet.app',
        redirectCallback: `${ORIGIN}/auth/return`,
      }),
    );
    expect(url.searchParams.get('callback')).toBe(`${ORIGIN}/auth/return`);
  });
});

describe('startRedirect', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
  });

  it('resolves null and clears pending state when browser Back restores the page', async () => {
    const storage = memoryStorage();
    const pending = startRedirect({
      appName: APP_NAME,
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      signetAppOrigin: `${JSDOM_ORIGIN}/#`,
      storage,
    });

    await settleMicrotasks();
    expect(await loadPendingRedirectFromStorage(storage)).not.toBeNull();

    dispatchPersistedPageShow();

    await expect(pending).resolves.toBeNull();
    expect(await loadPendingRedirectFromStorage(storage)).toBeNull();
  });
});

describe('consumeCallback', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns no-callback when URL has no auth params', () => {
    setLocation('?other=foo');
    const result = consumeCallback();
    expect(result.kind).toBe('no-callback');
  });

  it('returns denied when error=denied is set, regardless of pending state', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation('?error=denied');
    const result = consumeCallback();
    expect(result.kind).toBe('denied');
    // Pending state cleared either way — stale records mustn't survive.
    expect(loadPendingRedirect()).toBeNull();
  });

  it('returns invalid when no pending state exists', () => {
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const result = consumeCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('no-pending-state');
    }
  });

  it('returns invalid on origin mismatch', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: 'https://attacker.example',  // different origin
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const result = consumeCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('origin-mismatch');
    }
    expect(loadPendingRedirect()).toBeNull();
  });

  it('returns invalid when pending state is stale', () => {
    const stale = Date.now() - PENDING_REDIRECT_TTL_MS - 1000;
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: stale,
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const result = consumeCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('pending-stale');
    }
  });

  it('rejects malformed pubkey / signature / eventId', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=notHex&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const r1 = consumeCallback();
    expect(r1.kind).toBe('invalid');

    // Re-stage pending — the previous call cleared it
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=tooShort&eventId=${EVENT_ID}`);
    const r2 = consumeCallback();
    expect(r2.kind).toBe('invalid');
  });

  it('builds a session when params are valid (with t)', () => {
    const t = Math.floor(Date.now() / 1000) - 5;
    const authEvent = makeAuthEvent({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      createdAt: t,
    });
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(callbackSearchForAuthEvent(authEvent, { display_name: 'Alice' }));
    const result = consumeCallback();
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.pubkey).toBe(authEvent.pubkey);
      expect(result.session.method).toBe('redirect');
      expect(result.session.signer.capabilities.canSignEvents).toBe(false);
      expect(result.session.authEvent.created_at).toBe(t);
      // No `app` tag — signet-app's signAuthChallenge (src/lib/signet.ts)
      // doesn't include one in the signed event, so reconstructing with
      // one would break the canonical event-ID hash for any strict
      // server-side verifier.
      expect(result.session.authEvent.tags).toEqual([
        ['challenge', CHALLENGE],
        ['origin', JSDOM_ORIGIN],
      ]);
      expect(result.session.displayName).toBe('Alice');
    }
    expect(loadPendingRedirect()).toBeNull();
  });

  it('rejects forged params when t is present', () => {
    const t = Math.floor(Date.now() / 1000) - 5;
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}&t=${t}`);
    const result = consumeCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('invalid-event-id');
    }
  });

  it('rejects legacy missing-t callbacks by default (secure by default)', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const result = consumeCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('t-required');
    }
    // Pending state must not survive a rejected callback either.
    expect(loadPendingRedirect()).toBeNull();
  });

  it('rejects missing-t callbacks when legacy compatibility is explicitly disabled', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const result = consumeCallback({ allowLegacyMissingTimestamp: false });
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('t-required');
    }
  });

  it('allows legacy missing-t callbacks only when explicitly opted in, and warns', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => { /* swallow */ });
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const before = Math.floor(Date.now() / 1000);
    const result = consumeCallback({ allowLegacyMissingTimestamp: true });
    const after = Math.floor(Date.now() / 1000);
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.authEvent.created_at).toBeGreaterThanOrEqual(before);
      expect(result.session.authEvent.created_at).toBeLessThanOrEqual(after);
    }
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it('is idempotent — second call after success returns no-callback', () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    // Exercises the legacy (unverified) opt-in path — the idempotency being
    // tested here is URL-stripping, not timestamp verification.
    const r1 = consumeCallback({ allowLegacyMissingTimestamp: true });
    expect(r1.kind).toBe('session');
    // URL has been stripped via history.replaceState — jsdom honours that
    const r2 = consumeCallback({ allowLegacyMissingTimestamp: true });
    expect(r2.kind).toBe('no-callback');
  });
});

describe('handleRedirectCallback', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
  });

  it('persists the session via the standard storage layer on success', async () => {
    const t = Math.floor(Date.now() / 1000);
    const authEvent = makeAuthEvent({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      createdAt: t,
    });
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(callbackSearchForAuthEvent(authEvent));

    const result = await handleRedirectCallback();
    expect(result.kind).toBe('session');

    // restoreSession should now find the persisted session
    const persisted = loadSession();
    expect(persisted).not.toBeNull();
    expect(persisted?.pubkey).toBe(authEvent.pubkey);
    expect(persisted?.method).toBe('redirect');
  });

  it('does not persist on denied or invalid', async () => {
    setLocation(`?error=denied`);
    const result = await handleRedirectCallback();
    expect(result.kind).toBe('denied');
    expect(loadSession()).toBeNull();
  });

  it('uses custom storage for pending state and persisted sessions', async () => {
    const storage = memoryStorage();
    await savePendingRedirectToStorage({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    }, storage);
    const t = Math.floor(Date.now() / 1000);
    const authEvent = makeAuthEvent({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      createdAt: t,
    });
    setLocation(callbackSearchForAuthEvent(authEvent));

    const result = await handleRedirectCallback({ storage });
    expect(result.kind).toBe('session');
    expect(loadSession()).toBeNull();

    const persisted = await loadSessionFromStorage(storage);
    expect(persisted?.pubkey).toBe(authEvent.pubkey);
    expect(persisted?.method).toBe('redirect');
  });

  it('passes strict missing-t policy through handleRedirectCallback', async () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);

    const result = await handleRedirectCallback({ allowLegacyRedirectWithoutTimestamp: false });
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('t-required');
    }
    expect(loadSession()).toBeNull();
  });

  it('rejects missing-t callbacks by default through handleRedirectCallback (secure by default)', async () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);

    const result = await handleRedirectCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') {
      expect(result.reason).toBe('t-required');
    }
    expect(loadSession()).toBeNull();
  });

  it('allows missing-t callbacks through handleRedirectCallback when explicitly opted in', async () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => { /* swallow */ });
    const result = await handleRedirectCallback({ allowLegacyRedirectWithoutTimestamp: true });
    warn.mockRestore();
    expect(result.kind).toBe('session');
    expect(loadSession()).not.toBeNull();
  });
});

// Avoid an unused-import lint complaint in CI: we import these constants for
// readability and to assert against the real values from the type module.
void STORAGE_KEYS;
void clearPendingRedirect;
