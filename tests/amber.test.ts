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
  it('produces a nostrsigner: URL with base64-encoded event', () => {
    const url = buildAmberSignerUrl({
      appName: 'Test',
      challenge: 'a'.repeat(64),
      origin: 'https://example.com',
    });
    expect(url).toMatch(/^nostrsigner:[A-Za-z0-9+/=]+\?/);
    expect(url).toContain('type=sign_event');
    expect(url).toContain('compressionType=base64');
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
    const eventB64 = url.replace(/^nostrsigner:/, '').split('?')[0]!;
    const json = atob(eventB64);
    const event = JSON.parse(json);
    expect(event.kind).toBe(21236);
    expect(event.content).toBe('');
    expect(event.tags).toContainEqual(['challenge', challenge]);
    expect(event.tags).toContainEqual(['origin', 'https://pallasite.app']);
    expect(event.tags).toContainEqual(['app', 'Pallasite']);
  });

  it('honours redirectCallback override', () => {
    const url = buildAmberSignerUrl({
      appName: 'Test',
      challenge: 'a'.repeat(64),
      origin: 'https://example.com',
      redirectCallback: 'https://example.com/auth/return',
    });
    expect(url).toContain('callbackUrl=https%3A%2F%2Fexample.com%2Fauth%2Freturn');
  });
});

describe('consumeAmberCallback', () => {
  beforeEach(() => {
    clearPendingRedirect();
    window.history.replaceState({}, '', '/');
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
