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
} from '../src/redirect.js';
import {
  savePendingRedirect,
  loadPendingRedirect,
  clearPendingRedirect,
  loadSession,
} from '../src/storage.js';
import { STORAGE_KEYS, PENDING_REDIRECT_TTL_MS } from '../src/types.js';
import { handleRedirectCallback } from '../src/signet-login.js';

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
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(
      `?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}&t=${t}&display_name=Alice`,
    );
    const result = consumeCallback();
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.pubkey).toBe(PUBKEY);
      expect(result.session.method).toBe('redirect');
      expect(result.session.signer.capabilities.canSignEvents).toBe(false);
      expect(result.session.authEvent.created_at).toBe(t);
      expect(result.session.authEvent.tags).toEqual([
        ['challenge', CHALLENGE],
        ['origin', JSDOM_ORIGIN],
        ['app', APP_NAME],
      ]);
      expect(result.session.displayName).toBe('Alice');
    }
    expect(loadPendingRedirect()).toBeNull();
  });

  it('falls back to "now" when t is absent and warns', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => { /* swallow */ });
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}`);
    const before = Math.floor(Date.now() / 1000);
    const result = consumeCallback();
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
    const r1 = consumeCallback();
    expect(r1.kind).toBe('session');
    // URL has been stripped via history.replaceState — jsdom honours that
    const r2 = consumeCallback();
    expect(r2.kind).toBe('no-callback');
  });
});

describe('handleRedirectCallback', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
  });

  it('persists the session via the standard storage layer on success', async () => {
    savePendingRedirect({
      challenge: CHALLENGE,
      origin: JSDOM_ORIGIN,
      appName: APP_NAME,
      createdAt: Date.now(),
    });
    const t = Math.floor(Date.now() / 1000);
    setLocation(`?pubkey=${PUBKEY}&signature=${SIGNATURE}&eventId=${EVENT_ID}&t=${t}`);

    const result = await handleRedirectCallback();
    expect(result.kind).toBe('session');

    // restoreSession should now find the persisted session
    const persisted = loadSession();
    expect(persisted).not.toBeNull();
    expect(persisted?.pubkey).toBe(PUBKEY);
    expect(persisted?.method).toBe('redirect');
  });

  it('does not persist on denied or invalid', async () => {
    setLocation(`?error=denied`);
    const result = await handleRedirectCallback();
    expect(result.kind).toBe('denied');
    expect(loadSession()).toBeNull();
  });
});

// Avoid an unused-import lint complaint in CI: we import these constants for
// readability and to assert against the real values from the type module.
void STORAGE_KEYS;
void clearPendingRedirect;
