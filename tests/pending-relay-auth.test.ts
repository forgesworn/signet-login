import { describe, it, expect, beforeEach } from 'vitest';
import {
  savePendingRelayAuth,
  loadPendingRelayAuth,
  clearPendingRelayAuth,
} from '../src/storage.js';
import { STORAGE_KEYS } from '../src/types.js';
import type { PendingRelayAuth } from '../src/types.js';

const AUTH_FRESHNESS_WINDOW_SEC = 300;

function makeRecord(overrides: Partial<PendingRelayAuth> = {}): PendingRelayAuth {
  return {
    challenge: 'a'.repeat(64),
    origin: 'https://consumer.test',
    appName: 'Consumer',
    relayUrl: 'wss://relay.test',
    sessionSkHex: 'b'.repeat(64),
    issuedAt: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

describe('pending relay auth persistence', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('round-trips a record', async () => {
    const record = makeRecord();
    await savePendingRelayAuth(record);
    expect(await loadPendingRelayAuth()).toEqual(record);
  });

  it('returns null when nothing is stored', async () => {
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it('drops a record whose validity window has passed', async () => {
    // The whole point of persisting is resuming a LIVE sign-in. A dead one must
    // not be resumed, and its session key must not linger.
    await savePendingRelayAuth(makeRecord({
      issuedAt: Math.floor(Date.now() / 1000) - (AUTH_FRESHNESS_WINDOW_SEC + 30),
    }));
    expect(await loadPendingRelayAuth()).toBeNull();
    expect(localStorage.getItem(STORAGE_KEYS.pendingRelayAuth)).toBeNull();
  });

  it('returns null and does not throw on malformed JSON', async () => {
    localStorage.setItem(STORAGE_KEYS.pendingRelayAuth, '{not json');
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it('returns null when a required field is missing', async () => {
    localStorage.setItem(
      STORAGE_KEYS.pendingRelayAuth,
      JSON.stringify({ challenge: 'a'.repeat(64), origin: 'https://consumer.test' }),
    );
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it('rejects a non-hex session key rather than handing it to the crypto layer', async () => {
    localStorage.setItem(
      STORAGE_KEYS.pendingRelayAuth,
      JSON.stringify(makeRecord({ sessionSkHex: 'not-hex' })),
    );
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it('clears a record', async () => {
    await savePendingRelayAuth(makeRecord());
    await clearPendingRelayAuth();
    expect(await loadPendingRelayAuth()).toBeNull();
  });
});
