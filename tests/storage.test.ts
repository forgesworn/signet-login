/**
 * Tests for localStorage persistence helpers.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import { saveSession, loadSession, clearSession, bytesToHexLocal, hexToBytesLocal } from '../src/storage.js';
import { STORAGE_KEYS } from '../src/types.js';

const fakePubkey = 'a'.repeat(64);
const fakeAuthEvent = {
  id: 'b'.repeat(64),
  pubkey: fakePubkey,
  kind: 21236,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['challenge', 'c'.repeat(64)], ['origin', 'https://x.example']],
  content: '',
  sig: 'd'.repeat(128),
};

describe('storage', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.useRealTimers();
  });

  it('round-trips a nip07 session', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'nip07',
      authEventJson: JSON.stringify(fakeAuthEvent),
    });
    const loaded = loadSession();
    expect(loaded).not.toBeNull();
    expect(loaded?.pubkey).toBe(fakePubkey);
    expect(loaded?.method).toBe('nip07');
    expect(JSON.parse(loaded!.authEventJson).id).toBe(fakeAuthEvent.id);
  });

  it('round-trips a bunker session with URI + client SK', () => {
    const sk = bytesToHexLocal(new Uint8Array(32).fill(7));
    saveSession({
      pubkey: fakePubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(fakeAuthEvent),
      bunkerUri: 'bunker://abc?relay=wss://relay.example',
      bunkerClientSkHex: sk,
    });
    const loaded = loadSession();
    expect(loaded?.bunkerUri).toBe('bunker://abc?relay=wss://relay.example');
    expect(loaded?.bunkerClientSkHex).toBe(sk);
  });

  it('clears a session', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'nip07',
      authEventJson: JSON.stringify(fakeAuthEvent),
    });
    clearSession();
    expect(loadSession()).toBeNull();
  });

  it('returns null for malformed pubkey', () => {
    localStorage.setItem(STORAGE_KEYS.pubkey, 'not-hex');
    localStorage.setItem(STORAGE_KEYS.method, 'nip07');
    localStorage.setItem(STORAGE_KEYS.authEvent, JSON.stringify(fakeAuthEvent));
    expect(loadSession()).toBeNull();
  });

  it('returns null for unknown method', () => {
    localStorage.setItem(STORAGE_KEYS.pubkey, fakePubkey);
    localStorage.setItem(STORAGE_KEYS.method, 'wat');
    localStorage.setItem(STORAGE_KEYS.authEvent, JSON.stringify(fakeAuthEvent));
    expect(loadSession()).toBeNull();
  });

  it('returns null when stored authEvent pubkey mismatches', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'nip07',
      authEventJson: JSON.stringify({ ...fakeAuthEvent, pubkey: 'e'.repeat(64) }),
    });
    expect(loadSession()).toBeNull();
  });

  it('drops an expired session', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(fakeAuthEvent),
      expiresAt: Date.now() - 1000,
    });
    expect(loadSession()).toBeNull();
    // clearSession should have been called
    expect(localStorage.getItem(STORAGE_KEYS.pubkey)).toBeNull();
  });

  it('keeps a session not yet expired', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(fakeAuthEvent),
      expiresAt: Date.now() + 60_000,
    });
    expect(loadSession()).not.toBeNull();
  });

  it('returns null if any required key missing', () => {
    expect(loadSession()).toBeNull();
  });

  it('hex round-trips bytes', () => {
    const original = new Uint8Array([0, 1, 2, 254, 255]);
    expect(hexToBytesLocal(bytesToHexLocal(original))).toEqual(original);
  });
});
