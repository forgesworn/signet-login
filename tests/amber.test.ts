/**
 * Unit tests for the Amber (NIP-55) sign-in flow.
 *
 * Coverage focuses on the URL builder and the callback parser. The
 * navigation step (`startAmberSignIn`) is not exercised here — jsdom
 * doesn't actually navigate, and the round-trip path needs a real
 * Android device with Amber installed (smoke-tested manually).
 */
import { describe, it, expect, beforeEach } from 'vitest';

import {
  amberCallbackUrl,
  buildAmberSignerUrl,
  consumeAmberCallback,
  isAndroid,
} from '../src/amber.js';
import { savePendingRedirect, clearPendingRedirect } from '../src/storage.js';
import { makeAuthEvent } from './helpers/auth-event.js';

describe('isAndroid', () => {
  beforeEach(() => {
    Object.defineProperty(window.navigator, 'userAgent', { configurable: true, value: 'Mozilla/5.0' });
  });

  it('returns false for non-Android UA', () => {
    expect(isAndroid()).toBe(false);
  });

  it('returns true for Android UA', () => {
    Object.defineProperty(window.navigator, 'userAgent', {
      configurable: true,
      value: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36',
    });
    expect(isAndroid()).toBe(true);
  });
});

describe('buildAmberSignerUrl', () => {
  it('produces a NIP-55 web URL: URL-encoded event JSON, compressionType none', () => {
    const url = buildAmberSignerUrl({
      appName: 'Test',
      challenge: 'a'.repeat(64),
      origin: 'https://example.com',
    });
    expect(url).toMatch(/^nostrsigner:%7B[^?]+\?/);
    expect(url).toContain('type=sign_event');
    expect(url).toContain('compressionType=none');
    expect(url).not.toContain('compressionType=base64');
    expect(url).toContain('returnType=event');
    expect(url).toContain('callbackUrl=');
  });

  it('decodes back into the original event template', () => {
    const challenge = 'a'.repeat(64);
    const url = buildAmberSignerUrl({
      appName: 'Pallasite',
      challenge,
      origin: 'https://pallasite.app',
    });
    const encoded = url.replace(/^nostrsigner:/, '').split('?')[0]!;
    const event = JSON.parse(decodeURIComponent(encoded));
    expect(event.kind).toBe(21236);
    expect(event.content).toBe('');
    expect(event.tags).toContainEqual(['challenge', challenge]);
    expect(event.tags).toContainEqual(['origin', 'https://pallasite.app']);
    expect(event.tags).toContainEqual(['app', 'Pallasite']);
  });

  it('honours redirectCallback override and still ends the callback in event=', () => {
    const url = buildAmberSignerUrl({
      appName: 'Test',
      challenge: 'a'.repeat(64),
      origin: 'https://example.com',
      redirectCallback: 'https://example.com/auth/return',
    });
    const callback = new URL(url.replace(/^nostrsigner:[^?]*\?/, 'https://x/?')).searchParams.get('callbackUrl');
    expect(callback).toBe('https://example.com/auth/return?signet_amber=1&event=');
  });

  // NIP-55 signers append the percent-encoded result to the end of the callback
  // URL (Amber: `callBackUrl + Uri.encode(value)`; Cambium's result builder does
  // the same), so the callback has to end in `event=` or the answer is never
  // the `event` parameter the consumer reads.
  it('defaults the callback to the origin root ending in event=', () => {
    const url = buildAmberSignerUrl({ appName: 'Test', challenge: 'a'.repeat(64), origin: 'https://example.com' });
    const callback = new URL(url.replace(/^nostrsigner:[^?]*\?/, 'https://x/?')).searchParams.get('callbackUrl');
    expect(callback).toBe('https://example.com/?signet_amber=1&event=');
  });

  it('joins the result parameters to a page with a query and drops a fragment', () => {
    expect(amberCallbackUrl('https://example.com/browse?next=%2Fstudio')).toBe('https://example.com/browse?next=%2Fstudio&signet_amber=1&event=');
    expect(amberCallbackUrl('https://example.com/invite#token')).toBe('https://example.com/invite?signet_amber=1&event=');
    expect(amberCallbackUrl('https://example.com/?')).toBe('https://example.com/?signet_amber=1&event=');
  });
});

describe('consumeAmberCallback', () => {
  beforeEach(() => {
    clearPendingRedirect();
    window.history.replaceState({}, '', '/');
  });

  it('accepts the answer a signer gives: the percent-encoded event appended to the built callback', () => {
    const challenge = 'a'.repeat(64);
    const url = buildAmberSignerUrl({ appName: 'Test', challenge, origin: window.location.origin, redirectCallback: `${window.location.origin}/browse?next=%2Fstudio` });
    const callback = new URL(url.replace(/^nostrsigner:[^?]*\?/, 'https://x/?')).searchParams.get('callbackUrl')!;
    const signed = makeAuthEvent({ challenge, origin: window.location.origin, appName: 'Test' });
    savePendingRedirect({ challenge, origin: window.location.origin, appName: 'Test', createdAt: Date.now() });
    const answer = new URL(callback + encodeURIComponent(JSON.stringify(signed)));
    window.history.replaceState({}, '', answer.pathname + answer.search);
    const result = consumeAmberCallback();
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.method).toBe('amber');
      expect(result.session.pubkey).toBe(signed.pubkey);
      expect(result.session.authEvent.id).toBe(signed.id);
    }
    expect(window.location.pathname + window.location.search).toBe('/browse?next=%2Fstudio');
  });

  it('returns no-callback when URL has no amber params', () => {
    const result = consumeAmberCallback();
    expect(result.kind).toBe('no-callback');
  });

  it('returns invalid:no-pending-state when the event arrives without prior pending', () => {
    window.history.replaceState({}, '', '/?signet_amber=1&event=abc');
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') expect(result.reason).toBe('no-pending-state');
  });

  it('returns denied when error=denied', () => {
    savePendingRedirect({
      challenge: 'a'.repeat(64),
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    window.history.replaceState({}, '', '/?signet_amber=1&error=denied');
    const result = consumeAmberCallback();
    expect(result.kind).toBe('denied');
  });

  it('returns invalid:event-malformed for non-base64 event', () => {
    savePendingRedirect({
      challenge: 'a'.repeat(64),
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent('!!!not-base64!!!'));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
  });

  it('returns invalid:challenge-mismatch when the signed event has a different challenge', () => {
    const pendingChallenge = 'a'.repeat(64);
    const signedWrongChallenge = makeAuthEvent({
      challenge: 'd'.repeat(64),
      origin: window.location.origin,
      appName: 'Test',
    });
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    const eventB64 = btoa(JSON.stringify(signedWrongChallenge));
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(eventB64));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') expect(result.reason).toBe('challenge-mismatch');
  });

  it('returns invalid:origin-mismatch when the signed event has a different origin', () => {
    const pendingChallenge = 'a'.repeat(64);
    const signedWrongOrigin = makeAuthEvent({
      challenge: pendingChallenge,
      origin: 'https://other.example',
      appName: 'Test',
    });
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    const eventB64 = btoa(JSON.stringify(signedWrongOrigin));
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(eventB64));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') expect(result.reason).toBe('origin-mismatch');
  });

  it('returns invalid:app-mismatch when the signed event has a different app tag', () => {
    const pendingChallenge = 'a'.repeat(64);
    const signedWrongApp = makeAuthEvent({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Other App',
    });
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    const eventB64 = btoa(JSON.stringify(signedWrongApp));
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(eventB64));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') expect(result.reason).toBe('app-mismatch');
  });

  it('rejects a forged event even when shape and challenge match', () => {
    const pendingChallenge = 'a'.repeat(64);
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    const fakeEvent = {
      id: 'b'.repeat(64),
      pubkey: 'c'.repeat(64),
      kind: 21236,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['challenge', pendingChallenge], ['origin', window.location.origin], ['app', 'Test']],
      content: '',
      sig: 'e'.repeat(128),
    };
    const eventB64 = btoa(JSON.stringify(fakeEvent));
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(eventB64));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('invalid');
    if (result.kind === 'invalid') expect(result.reason).toBe('invalid-event-id');
  });

  it('builds a session for a signed callback', () => {
    const pendingChallenge = 'a'.repeat(64);
    const event = makeAuthEvent({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
    });
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    const eventB64 = btoa(JSON.stringify(event));
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(eventB64));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.method).toBe('amber');
      expect(result.session.pubkey).toBe(event.pubkey);
      expect(result.session.signer.capabilities.canSignEvents).toBe(false);
    }
  });

  it('builds a session from a plain JSON reply (compressionType none, as Cambium sends)', () => {
    const pendingChallenge = 'b'.repeat(64);
    const event = makeAuthEvent({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
    });
    savePendingRedirect({
      challenge: pendingChallenge,
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    window.history.replaceState({}, '', '/?signet_amber=1&event=' + encodeURIComponent(JSON.stringify(event)));
    const result = consumeAmberCallback();
    expect(result.kind).toBe('session');
    if (result.kind === 'session') expect(result.session.pubkey).toBe(event.pubkey);
  });

  it('strips amber params from the URL after consume', () => {
    savePendingRedirect({
      challenge: 'a'.repeat(64),
      origin: window.location.origin,
      appName: 'Test',
      createdAt: Date.now(),
    });
    window.history.replaceState({}, '', '/?signet_amber=1&error=denied&keep=this');
    consumeAmberCallback();
    expect(window.location.search).toBe('?keep=this');
  });
});
