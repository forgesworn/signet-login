/**
 * Tests for localStorage persistence helpers.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import {
  saveSession,
  saveSessionToStorage,
  loadSession,
  loadSessionFromStorage,
  clearSession,
  clearSessionFromStorage,
  bytesToHexLocal,
  hexToBytesLocal,
  loadOrCreatePersistentClientSk,
  loadOrCreatePersistentClientSkFromStorage,
  clearPersistentClientSk,
  savePendingRedirectToStorage,
  loadPendingRedirectFromStorage,
  clearPendingRedirectFromStorage,
} from '../src/storage.js';
import { makeAuthEvent } from './helpers/auth-event.js';
import { STORAGE_KEYS, type SignetStorage } from '../src/types.js';

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

function memoryStorage(): SignetStorage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    async compareAndSetItem(key: string, expected: string | null, value: string | null) {
      if ((data.get(key) ?? null) !== expected) return false;
      if(value === null) data.delete(key); else data.set(key, value); return true;
    },
    async getItems(keys: readonly string[]) { return Object.fromEntries(keys.map(key => [key, data.get(key) ?? null])); },
    async setItems(changes: Readonly<Record<string, string | null>>, expected: Readonly<Record<string, string | null>>) {
      if(Object.entries(expected).some(([key,value])=>(data.get(key) ?? null)!==value)) return false;
      for (const [key, value] of Object.entries(changes)) { if (value === null) data.delete(key); else data.set(key, value); } return true;
    },
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

  it('clears stale optional fields when overwriting a session', () => {
    saveSession({
      pubkey: fakePubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(fakeAuthEvent),
      bunkerUri: 'bunker://abc?relay=wss://relay.example',
      bunkerClientSkHex: bytesToHexLocal(new Uint8Array(32).fill(4)),
      expiresAt: Date.now() + 60_000,
      displayName: 'Alice',
    });
    saveSession({
      pubkey: fakePubkey,
      method: 'redirect',
      authEventJson: JSON.stringify(fakeAuthEvent),
    });

    expect(localStorage.getItem(STORAGE_KEYS.bunkerUri)).toBeNull();
    expect(localStorage.getItem(STORAGE_KEYS.bunkerClientSk)).toBeNull();
    expect(localStorage.getItem(STORAGE_KEYS.expiresAt)).toBeNull();
    expect(localStorage.getItem(STORAGE_KEYS.displayName)).toBeNull();
    expect(loadSession()?.method).toBe('redirect');
  });

  it('returns null if any required key missing', () => {
    expect(loadSession()).toBeNull();
  });

  it('hex round-trips bytes', () => {
    const original = new Uint8Array([0, 1, 2, 254, 255]);
    expect(hexToBytesLocal(bytesToHexLocal(original))).toEqual(original);
  });

  describe('persistent client key', () => {
    it('generates a 32-byte key and persists it', () => {
      const sk = loadOrCreatePersistentClientSk();
      expect(sk).toBeInstanceOf(Uint8Array);
      expect(sk.length).toBe(32);
      expect(localStorage.getItem(STORAGE_KEYS.clientSk)).toBe(bytesToHexLocal(sk));
    });

    it('returns the same key on subsequent calls', () => {
      const first = loadOrCreatePersistentClientSk();
      const second = loadOrCreatePersistentClientSk();
      expect(bytesToHexLocal(second)).toBe(bytesToHexLocal(first));
    });

    it('survives clearSession (it is not session state)', () => {
      const sk = loadOrCreatePersistentClientSk();
      clearSession();
      expect(localStorage.getItem(STORAGE_KEYS.clientSk)).toBe(bytesToHexLocal(sk));
      expect(bytesToHexLocal(loadOrCreatePersistentClientSk())).toBe(bytesToHexLocal(sk));
    });

    it('regenerates after an explicit reset', () => {
      const first = bytesToHexLocal(loadOrCreatePersistentClientSk());
      clearPersistentClientSk();
      expect(localStorage.getItem(STORAGE_KEYS.clientSk)).toBeNull();
      const second = bytesToHexLocal(loadOrCreatePersistentClientSk());
      expect(second).not.toBe(first);
    });

    it('regenerates a corrupt stored value', () => {
      localStorage.setItem(STORAGE_KEYS.clientSk, 'not-hex');
      const sk = loadOrCreatePersistentClientSk();
      expect(sk.length).toBe(32);
      expect(localStorage.getItem(STORAGE_KEYS.clientSk)).toBe(bytesToHexLocal(sk));
    });
  });

  describe('custom async storage', () => {
    it('round-trips and clears a session without touching localStorage', async () => {
      const store = memoryStorage();
      await saveSessionToStorage({
        pubkey: fakePubkey,
        method: 'nip07',
        authEventJson: JSON.stringify(fakeAuthEvent),
        displayName: 'Alice',
      }, store);

      expect(localStorage.getItem(STORAGE_KEYS.pubkey)).toBeNull();
      const loaded = await loadSessionFromStorage(store);
      expect(loaded?.pubkey).toBe(fakePubkey);
      expect(loaded?.displayName).toBe('Alice');

      await clearSessionFromStorage(store);
      expect(await loadSessionFromStorage(store)).toBeNull();
    });

    it('clears stale optional fields when overwriting in custom storage', async () => {
      const store = memoryStorage();
      await saveSessionToStorage({
        pubkey: fakePubkey,
        method: 'bunker',
        authEventJson: JSON.stringify(fakeAuthEvent),
        bunkerUri: 'bunker://abc?relay=wss://relay.example',
        bunkerClientSkHex: bytesToHexLocal(new Uint8Array(32).fill(5)),
        expiresAt: Date.now() + 60_000,
        displayName: 'Alice',
      }, store);
      await saveSessionToStorage({
        pubkey: fakePubkey,
        method: 'redirect',
        authEventJson: JSON.stringify(fakeAuthEvent),
      }, store);

      expect(store.data.has(STORAGE_KEYS.bunkerUri)).toBe(false);
      expect(store.data.has(STORAGE_KEYS.bunkerClientSk)).toBe(false);
      expect(store.data.has(STORAGE_KEYS.expiresAt)).toBe(false);
      expect(store.data.has(STORAGE_KEYS.displayName)).toBe(false);
    });

    it('drops expired sessions from custom storage', async () => {
      const store = memoryStorage();
      await saveSessionToStorage({
        pubkey: fakePubkey,
        method: 'redirect',
        authEventJson: JSON.stringify(fakeAuthEvent),
        expiresAt: Date.now() - 1000,
      }, store);

      expect(await loadSessionFromStorage(store)).toBeNull();
      expect(store.data.has(STORAGE_KEYS.pubkey)).toBe(false);
    });

    it('persists the stable NIP-46 client key in custom storage', async () => {
      const store = memoryStorage();
      const first = await loadOrCreatePersistentClientSkFromStorage(store);
      const second = await loadOrCreatePersistentClientSkFromStorage(store);

      expect(bytesToHexLocal(second)).toBe(bytesToHexLocal(first));
      expect(localStorage.getItem(STORAGE_KEYS.clientSk)).toBeNull();
      expect(store.data.get(STORAGE_KEYS.clientSk)).toBe(bytesToHexLocal(first));
    });

    it('round-trips pending redirect state in custom storage', async () => {
      const store = memoryStorage();
      const pending = {
        challenge: 'f'.repeat(64),
        origin: 'https://example.test',
        appName: 'Test App',
        createdAt: Date.now(),
      };

      await savePendingRedirectToStorage(pending, store);
      expect(await loadPendingRedirectFromStorage(store)).toEqual(pending);
      await clearPendingRedirectFromStorage(store);
      expect(await loadPendingRedirectFromStorage(store)).toBeNull();
    });
  });
});

describe('required custom custody', () => {
  const failure = new Error('custody held');
  it('propagates a failed read before generating or writing a replacement client key', async () => {
    const random = vi.spyOn(crypto, 'getRandomValues');
    const setItem = vi.fn(async () => {});
    const store: SignetStorage = { required: true, compareAndSetItem: async () => true, getItem: async () => { throw failure; }, setItem, removeItem: async () => {} };
    try {
      await expect(loadOrCreatePersistentClientSkFromStorage(store)).rejects.toBe(failure);
      expect(random).not.toHaveBeenCalled(); expect(setItem).not.toHaveBeenCalled();
    } finally { random.mockRestore(); }
  });
  for (const invalid of ['', 'not-hex', '00'.repeat(32), 'ff'.repeat(32)]) it(`preserves an invalid existing client key without replacement: ${invalid.length ? invalid.slice(0, 6) : 'empty'}`, async () => {
    const store = { ...memoryStorage(), required: true };
    store.data.set(STORAGE_KEYS.clientSk, invalid);
    const random = vi.spyOn(crypto, 'getRandomValues');
    try {
      await expect(loadOrCreatePersistentClientSkFromStorage(store)).rejects.toThrow('required-storage-invalid-client-key');
      expect(random).not.toHaveBeenCalled(); expect(store.data.get(STORAGE_KEYS.clientSk)).toBe(invalid);
    } finally { random.mockRestore(); }
  });
  it('wipes the actual provisional key when native retention rejects', async () => {
    let generated: Uint8Array | undefined;
    const nativeRandom = crypto.getRandomValues.bind(crypto);
    const random = vi.spyOn(crypto, 'getRandomValues').mockImplementation(array => {
      const result = nativeRandom(array);
      generated = array as Uint8Array; return result;
    });
    const store: SignetStorage = { required: true, compareAndSetItem: async () => { throw failure; }, getItem: async () => null, setItem: async () => { throw failure; }, removeItem: async () => {} };
    try {
      await expect(loadOrCreatePersistentClientSkFromStorage(store)).rejects.toBe(failure);
      expect(generated?.length).toBe(32); expect(generated?.every(byte => byte === 0)).toBe(true);
    } finally { random.mockRestore(); }
  });
  it('keeps the exact new client key private until the backend acknowledges it', async () => {
    let acknowledge!: () => void, retained: string | undefined, returned = false;
    const receipt = new Promise<void>(resolve => { acknowledge = resolve; });
    const store: SignetStorage = { required: true, getItem: async () => null, compareAndSetItem: async (_key, _expected, value) => { retained = value!; await receipt; return true; },
      setItem: async () => {}, removeItem: async () => {} };
    const work = loadOrCreatePersistentClientSkFromStorage(store).then(key => { returned = true; return key; });
    for(let i=0;i<4;i++) await Promise.resolve();
    expect(retained).toMatch(/^[0-9a-f]{64}$/); expect(returned).toBe(false);
    acknowledge(); const key = await work;
    expect(bytesToHexLocal(key)).toBe(retained); key.fill(0);
  });
  it('propagates session write and logout deletion failures without acknowledging success', async () => {
    const store: SignetStorage = { required: true, compareAndSetItem: async () => { throw failure; }, getItem: async () => null, setItem: async () => { throw failure; }, removeItem: async () => { throw failure; }, setItems: async () => { throw failure; }, getItems: async keys => Object.fromEntries(keys.map(key=>[key,null])) };
    const event = makeAuthEvent({ challenge: 'a'.repeat(64), origin: window.location.origin });
    await expect(saveSessionToStorage({ pubkey: event.pubkey, method: 'nip07', authEventJson: JSON.stringify(event) }, store)).rejects.toBe(failure);
    await expect(clearSessionFromStorage(store)).rejects.toBe(failure);
    await expect(savePendingRedirectToStorage({ challenge: 'a'.repeat(64), origin: 'https://example.test', appName: 'KithMoot', createdAt: 1 }, store)).rejects.toBe(failure);
  });
  it('holds partial or malformed stored sessions without clearing their bytes', async () => {
    const store = { ...memoryStorage(), required: true };
    store.data.set(STORAGE_KEYS.pubkey, fakePubkey);
    await expect(loadSessionFromStorage(store)).rejects.toThrow('required-storage-invalid-session');
    expect([...store.data]).toEqual([[STORAGE_KEYS.pubkey, fakePubkey]]);
  });
  it('allows an authenticated backend to prove an absent session', async () => {
    await expect(loadSessionFromStorage({ ...memoryStorage(), required: true })).resolves.toBeNull();
  });
  it('retains best-effort compatibility for a backend that has not opted in', async () => {
    const store: SignetStorage = { getItem: async () => { throw failure; }, setItem: async () => { throw failure; }, removeItem: async () => { throw failure; } };
    const key = await loadOrCreatePersistentClientSkFromStorage(store);
    expect(key).toHaveLength(32); key.fill(0);
    await expect(clearSessionFromStorage(store)).resolves.toBeUndefined();
  });
});
