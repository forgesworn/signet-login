import { describe, expect, it } from 'vitest';

import {
  createLocalSignerFromNsec,
  createLoginAuthEvent,
  createSessionFromSigner,
  logout,
} from '../src/signet-login.js';
import { loadSessionFromStorage, saveSessionToStorage } from '../src/storage.js';
import type { SignetStorage } from '../src/types.js';

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

describe('headless helpers', () => {
  const privateKeyHex = '01'.repeat(32);
  const challenge = 'ab'.repeat(32);

  it('creates the same kind-21236 auth proof shape used by the modal', async () => {
    const signer = createLocalSignerFromNsec(privateKeyHex);
    const authEvent = await createLoginAuthEvent(signer, {
      appName: 'Headless App',
      challenge,
      origin: 'https://example.com',
    });

    expect(authEvent.kind).toBe(21236);
    expect(authEvent.pubkey).toBe(signer.pubkey);
    expect(authEvent.tags).toContainEqual(['challenge', challenge]);
    expect(authEvent.tags).toContainEqual(['origin', 'https://example.com']);
    expect(authEvent.tags).toContainEqual(['app', 'Headless App']);
    expect(authEvent.id).toMatch(/^[0-9a-f]{64}$/);
    expect(authEvent.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('creates a SignetSession from an already-connected signer', async () => {
    const signer = createLocalSignerFromNsec(privateKeyHex);
    const session = await createSessionFromSigner(signer, {
      appName: 'Headless App',
      challenge,
      origin: 'https://example.com',
    });

    expect(session.pubkey).toBe(signer.pubkey);
    expect(session.method).toBe('nsec');
    expect(session.signer).toBe(signer);
    expect(session.authEvent.kind).toBe(21236);
  });

  it('validates app name and challenge', async () => {
    const signer = createLocalSignerFromNsec(privateKeyHex);
    await expect(createLoginAuthEvent(signer, { appName: '', challenge })).rejects.toThrow(/appName-required/);
    await expect(createLoginAuthEvent(signer, { appName: 'Headless App', challenge: 'nope' })).rejects.toThrow(/challenge-must-be-64-hex/);
  });

  it('clears custom storage on logout', async () => {
    const storage = memoryStorage();
    const signer = createLocalSignerFromNsec(privateKeyHex);
    const session = await createSessionFromSigner(signer, {
      appName: 'Headless App',
      challenge,
      origin: 'https://example.com',
    });
    await saveSessionToStorage({
      pubkey: session.pubkey,
      method: 'redirect',
      authEventJson: JSON.stringify(session.authEvent),
    }, storage);

    expect(await loadSessionFromStorage(storage)).not.toBeNull();
    await logout(session, { storage });
    expect(await loadSessionFromStorage(storage)).toBeNull();
  });
});
