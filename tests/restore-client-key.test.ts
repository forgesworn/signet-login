import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Partial mock of signers.js: keep real implementations, but intercept
// createBunkerSigner so we can control reconnect behaviour without network.
vi.mock('../src/signers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/signers.js')>();
  return {
    ...actual,
    createBunkerSigner: vi.fn(actual.createBunkerSigner),
  };
});

import {
  createLocalSignerFromNsec,
  createLoginAuthEvent,
  restoreSession,
  logout,
} from '../src/signet-login.js';
import { createBunkerSigner } from '../src/signers.js';
import {
  saveSessionToStorage,
  loadSessionFromStorage,
  loadOrCreatePersistentClientSkFromStorage,
  clearPersistentClientSkFromStorage,
  decodeClientSecretKey,
  bytesToHexLocal,
} from '../src/storage.js';
import {
  STORAGE_KEYS,
  type SignetAuthEvent,
  type SignetStorage,
} from '../src/types.js';

// ── helpers ──────────────────────────────────────────────────────────────────

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

const APP = 'Restore Test App';
const ORIGIN = 'https://example.com';
const NSEC = '01'.repeat(32);

interface StoredBunkerProof {
  pubkey: string;
  authEvent: SignetAuthEvent;
  bunkerUri: string;
  clientSkHex: string;
  clientSk: Uint8Array;
}

/**
 * Build a real, signed kind-21236 auth event bound to the given (already
 * derived) pubkey, plus a matching session-client secret key. The auth event
 * is genuinely signed by the local nsec signer — no fake signatures — so the
 * stored proof will pass any validator that checks id/sig/challenge/origin/app.
 */
async function buildSignedBunkerProof(): Promise<StoredBunkerProof> {
  const signer = createLocalSignerFromNsec(NSEC);
  const challenge = Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0'),
  ).join('');
  const authEvent = await createLoginAuthEvent(signer, {
    appName: APP,
    challenge,
    origin: ORIGIN,
  });

  const clientSk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) clientSk[i] = (i * 7 + 3) & 0xff;
  const clientSkHex = bytesToHexLocal(clientSk);

  return {
    pubkey: signer.pubkey,
    authEvent,
    bunkerUri: 'bunker://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef?relay=wss%3A%2F%2Frelay.example',
    clientSkHex,
    clientSk,
  };
}

/** Persist a full bunker session, including the per-session client sk. */
async function persistBunkerSession(
  storage: SignetStorage,
  proof: StoredBunkerProof,
  overrides: Partial<{ bunkerClientSkHex: string; bunkerUri: string }> = {},
): Promise<void> {
  await saveSessionToStorage(
    {
      pubkey: proof.pubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(proof.authEvent),
      bunkerUri: overrides.bunkerUri ?? proof.bunkerUri,
      bunkerClientSkHex: overrides.bunkerClientSkHex ?? proof.clientSkHex,
    },
    storage,
  );
}

/**
 * Install a createBunkerSigner mock that behaves like a live signer for the
 * given session client key. It asserts (via the returned spy) that restore
 * handed it the SESSION's key, not the global persistent key, and returns a
 * minimal BunkerSignerImpl-shaped stub whose pubkey matches the stored one.
 */
function stubSuccessfulReconnect(expectedPubkey: string) {
  const mock = vi.mocked(createBunkerSigner);
  mock.mockImplementation(async (opts: unknown) => {
    const o = opts as { clientSecretKey: Uint8Array };
    return {
      pubkey: expectedPubkey,
      method: 'bunker' as const,
      bunkerUri: (opts as { uri: string }).uri,
      clientSecretKey: o.clientSecretKey,
      async signEvent() {
        throw new Error('not used in tests');
      },
      async close() {},
      nip46: {
        async logout() {},
      },
    } as unknown as Awaited<ReturnType<typeof createBunkerSigner>>;
  });
  return mock;
}

// ── tests ────────────────────────────────────────────────────────────────────

describe('restoreSession: session client-key handling', () => {
  let storage: SignetStorage;

  beforeEach(() => {
    storage = memoryStorage();
  });

  afterEach(() => {
    vi.mocked(createBunkerSigner).mockReset();
  });

  it('clears the session when bunkerClientSkHex is missing and never falls back to the global client key', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof, { bunkerClientSkHex: '' });

    // Seed a DIFFERENT global persistent client key. If restore ever used it,
    // the mock would be called with that key instead of bailing out.
    await loadOrCreatePersistentClientSkFromStorage(storage);

    const mock = vi.mocked(createBunkerSigner);
    mock.mockReset();

    const session = await restoreSession({ storage });

    expect(session).toBeNull();
    expect(mock).not.toHaveBeenCalled();
    expect(await loadSessionFromStorage(storage)).toBeNull();
    // Global key must be untouched.
    const globalSk = await storage.getItem(STORAGE_KEYS.clientSk);
    expect(globalSk).not.toBeNull();
  });

  it('clears the session when bunkerClientSkHex is malformed and never calls createBunkerSigner', async () => {
    const proof = await buildSignedBunkerProof();
    // 'not-hex' and an odd-length hex string are both rejected by the strict
    // decoder. Neither triggers a global-key fallback.
    await persistBunkerSession(storage, proof, { bunkerClientSkHex: 'not-hex-at-all' });
    await loadOrCreatePersistentClientSkFromStorage(storage);

    const mock = vi.mocked(createBunkerSigner);
    mock.mockReset();

    const session = await restoreSession({ storage });

    expect(session).toBeNull();
    expect(mock).not.toHaveBeenCalled();
    expect(await loadSessionFromStorage(storage)).toBeNull();
  });

  it('on transient reconnect failure, preserves the stored session key for the next retry', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof);

    const mock = vi.mocked(createBunkerSigner);
    mock.mockReset();
    mock.mockRejectedValueOnce(new Error('relay unreachable'));

    const session = await restoreSession({ storage });

    expect(session).toBeNull();
    // The stored session must NOT be cleared on transient failure — the next
    // restore has to retry with the SAME session key.
    const stored = await loadSessionFromStorage(storage);
    expect(stored).not.toBeNull();
    expect(stored?.bunkerClientSkHex).toBe(proof.clientSkHex);
    expect(stored?.pubkey).toBe(proof.pubkey);
  });

  it('passes the SESSION client key (never the global key) to createBunkerSigner', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof);

    // Seed a different global key to make a fallback observable.
    const globalSk = await loadOrCreatePersistentClientSkFromStorage(storage);
    // Overwrite global with a known-different value.
    const otherGlobal = new Uint8Array(32).fill(0xab);
    await storage.setItem(STORAGE_KEYS.clientSk, bytesToHexLocal(otherGlobal));

    const mock = stubSuccessfulReconnect(proof.pubkey);

    const session = await restoreSession({ storage });

    expect(session).not.toBeNull();
    expect(session?.pubkey).toBe(proof.pubkey);
    expect(session?.method).toBe('bunker');
    expect(mock).toHaveBeenCalledTimes(1);

    const callArg = mock.mock.calls[0][0] as { clientSecretKey: Uint8Array; uri: string };
    expect(bytesToHexLocal(callArg.clientSecretKey)).toBe(proof.clientSkHex);
    expect(bytesToHexLocal(callArg.clientSecretKey)).not.toBe(bytesToHexLocal(otherGlobal));
    expect(bytesToHexLocal(callArg.clientSecretKey)).not.toBe(bytesToHexLocal(globalSk));
  });

  it('on reconnected pubkey mismatch, closes the signer and clears the session', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof);

    const mismatchPubkey = 'f'.repeat(64);
    const closeSpy = vi.fn(async () => {});
    const mock = vi.mocked(createBunkerSigner);
    mock.mockReset();
    mock.mockImplementationOnce(async () =>
      ({
        pubkey: mismatchPubkey,
        method: 'bunker' as const,
        bunkerUri: proof.bunkerUri,
        clientSecretKey: proof.clientSk,
        async signEvent() {
          throw new Error('not used in tests');
        },
        close: closeSpy,
      } as unknown) as Awaited<ReturnType<typeof createBunkerSigner>>,
    );

    const session = await restoreSession({ storage });

    expect(session).toBeNull();
    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(await loadSessionFromStorage(storage)).toBeNull();
  });

  it('when the global key is absent, still uses the session key (never generates a new one)', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof);

    // Deliberately do not populate STORAGE_KEYS.clientSk.
    expect(await storage.getItem(STORAGE_KEYS.clientSk)).toBeNull();

    const mock = stubSuccessfulReconnect(proof.pubkey);

    const session = await restoreSession({ storage });

    expect(session).not.toBeNull();
    expect(mock).toHaveBeenCalledTimes(1);
    const callArg = mock.mock.calls[0][0] as { clientSecretKey: Uint8Array };
    expect(bytesToHexLocal(callArg.clientSecretKey)).toBe(proof.clientSkHex);
    // Global key must still be absent: restore must not have written one.
    expect(await storage.getItem(STORAGE_KEYS.clientSk)).toBeNull();
  });
});

describe('logout: clearPersistentClientKey', () => {
  let storage: SignetStorage;

  beforeEach(() => {
    storage = memoryStorage();
  });

  afterEach(() => {
    vi.mocked(createBunkerSigner).mockReset();
  });

  it('logout(undefined, { storage, clearPersistentClientKey: true }) removes both session and global key, and next restore never calls signer', async () => {
    const proof = await buildSignedBunkerProof();
    await persistBunkerSession(storage, proof);
    await loadOrCreatePersistentClientSkFromStorage(storage);

    // Sanity: both are present before logout.
    expect(await loadSessionFromStorage(storage)).not.toBeNull();
    expect(await storage.getItem(STORAGE_KEYS.clientSk)).not.toBeNull();

    await logout(undefined, { storage, clearPersistentClientKey: true });

    expect(await loadSessionFromStorage(storage)).toBeNull();
    expect(await storage.getItem(STORAGE_KEYS.clientSk)).toBeNull();
    expect(await storage.getItem(STORAGE_KEYS.bunkerClientSk)).toBeNull();
    expect(await storage.getItem(STORAGE_KEYS.bunkerUri)).toBeNull();

    const mock = vi.mocked(createBunkerSigner);
    mock.mockReset();
    const session = await restoreSession({ storage });
    expect(session).toBeNull();
    expect(mock).not.toHaveBeenCalled();
  });
});

describe('decodeClientSecretKey', () => {
  it('returns null for null and undefined', () => {
    expect(decodeClientSecretKey(null)).toBeNull();
    expect(decodeClientSecretKey(undefined)).toBeNull();
  });

  it('returns null for empty and malformed strings', () => {
    expect(decodeClientSecretKey('')).toBeNull();
    expect(decodeClientSecretKey('not-hex')).toBeNull();
    expect(decodeClientSecretKey('ab'.repeat(31))).toBeNull(); // 62 hex
    expect(decodeClientSecretKey('ab'.repeat(33))).toBeNull(); // 66 hex
    expect(decodeClientSecretKey('z'.repeat(64))).toBeNull(); // non-hex chars
  });

  it('accepts uppercase hex and returns the 32-byte decoding', () => {
    const upper = 'AB'.repeat(32);
    const decoded = decodeClientSecretKey(upper);
    expect(decoded).not.toBeNull();
    expect(decoded?.length).toBe(32);
    expect(decoded?.[0]).toBe(0xab);
    expect(decoded?.[31]).toBe(0xab);
  });

  it('returns bytes for a 64-hex all-zero key (validator rejects zero/out-of-range downstream)', () => {
    // The decoder itself is a pure hex→bytes function; it does NOT reject
    // all-zero bytes. createBunkerSigner is the component that must reject
    // invalid scalars (0 or >= curve order). This test documents that boundary:
    // the decoder returns bytes, it does not claim to validate the scalar.
    const decoded = decodeClientSecretKey('00'.repeat(32));
    expect(decoded).not.toBeNull();
    expect(decoded?.length).toBe(32);
    expect(Array.from(decoded ?? []).every((b) => b === 0)).toBe(true);
  });
});
