/**
 * Tests for the signer wrappers (Nip07Signer + EphemeralSigner).
 *
 * BunkerSigner is integration-only — its NIP-46 round-trip needs a real
 * bunker. Covered by manual / E2E tests, not unit tests here.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import { hasNip07, createNip07Signer, Nip07Signer, EphemeralSigner } from '../src/signers.js';

describe('hasNip07', () => {
  beforeEach(() => {
    delete (window as unknown as { nostr?: unknown }).nostr;
  });

  it('returns false when no extension is present', () => {
    expect(hasNip07()).toBe(false);
  });

  it('returns true when window.nostr is set', () => {
    (window as unknown as { nostr: unknown }).nostr = {
      getPublicKey: async () => 'a'.repeat(64),
      signEvent: async (e: unknown) => e,
    };
    expect(hasNip07()).toBe(true);
  });

  it('returns false when window.nostr lacks signEvent', () => {
    (window as unknown as { nostr: unknown }).nostr = { getPublicKey: async () => 'a'.repeat(64) };
    expect(hasNip07()).toBe(false);
  });
});

describe('createNip07Signer', () => {
  beforeEach(() => {
    delete (window as unknown as { nostr?: unknown }).nostr;
  });

  it('throws when no provider is present', async () => {
    await expect(createNip07Signer()).rejects.toThrow(/no-nip07-provider/);
  });

  it('throws when getPublicKey returns garbage', async () => {
    (window as unknown as { nostr: unknown }).nostr = {
      getPublicKey: async () => 'not-hex',
      signEvent: async () => ({}),
    };
    await expect(createNip07Signer()).rejects.toThrow(/invalid-pubkey-from-nip07/);
  });

  it('returns a working signer with capabilities', async () => {
    const fakePub = 'f'.repeat(64);
    const signEventMock = vi.fn(async (e: unknown) => ({ ...(e as object), id: '0', sig: '0', pubkey: fakePub }));
    (window as unknown as { nostr: unknown }).nostr = {
      getPublicKey: async () => fakePub.toUpperCase(),
      signEvent: signEventMock,
      nip44: {
        encrypt: async (_p: string, t: string) => `enc(${t})`,
        decrypt: async (_p: string, c: string) => c.replace(/^enc\(|\)$/g, ''),
      },
    };
    const signer = await createNip07Signer();
    expect(signer.pubkey).toBe(fakePub); // lowercased
    expect(signer.capabilities).toEqual({ canSignEvents: true, hasNip44: true });
    expect(signer.method).toBe('nip07');
    expect(signer.nip44).toBeDefined();

    await signer.signEvent({ kind: 1, content: 'hi' });
    expect(signEventMock).toHaveBeenCalledOnce();

    const ct = await signer.nip44!.encrypt('peer', 'hello');
    expect(ct).toBe('enc(hello)');

    await signer.close(); // no-op, just shouldn't throw
  });

  it('omits nip44 when extension does not provide it', async () => {
    const fakePub = 'a'.repeat(64);
    (window as unknown as { nostr: unknown }).nostr = {
      getPublicKey: async () => fakePub,
      signEvent: async (e: unknown) => e,
    };
    const signer = await createNip07Signer();
    expect(signer.capabilities.hasNip44).toBe(false);
    expect(signer.nip44).toBeUndefined();
  });
});

describe('EphemeralSigner', () => {
  it('exposes pubkey + capabilities { canSignEvents: false }', () => {
    const fakeAuthEvent = {
      id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      kind: 21236 as const,
      created_at: 1,
      tags: [],
      content: '',
      sig: 'c'.repeat(128),
    };
    const signer = new EphemeralSigner(fakeAuthEvent.pubkey, fakeAuthEvent);
    expect(signer.pubkey).toBe(fakeAuthEvent.pubkey);
    expect(signer.capabilities.canSignEvents).toBe(false);
    expect(signer.method).toBe('redirect');
  });

  it('throws on signEvent', async () => {
    const signer = new EphemeralSigner('a'.repeat(64), {
      id: 'a'.repeat(64),
      pubkey: 'a'.repeat(64),
      kind: 21236,
      created_at: 1,
      tags: [],
      content: '',
      sig: 'a'.repeat(128),
    });
    await expect(signer.signEvent({ kind: 1, content: '' })).rejects.toThrow(/signer-auth-only/);
  });

  it('close() is safe to call', async () => {
    const signer = new EphemeralSigner('a'.repeat(64), {
      id: 'a'.repeat(64),
      pubkey: 'a'.repeat(64),
      kind: 21236,
      created_at: 1,
      tags: [],
      content: '',
      sig: 'a'.repeat(128),
    });
    await expect(signer.close()).resolves.toBeUndefined();
  });
});

describe('Nip07Signer constructor', () => {
  it('reflects nip44 absence in capabilities', () => {
    const provider = {
      getPublicKey: async () => 'a'.repeat(64),
      signEvent: async (e: unknown) => e as never,
    };
    const signer = new Nip07Signer('a'.repeat(64), provider);
    expect(signer.capabilities.hasNip44).toBe(false);
  });
});
