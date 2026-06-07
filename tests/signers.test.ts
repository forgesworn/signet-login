/**
 * Tests for the signer wrappers (Nip07Signer + EphemeralSigner).
 *
 * BunkerSigner is integration-only — its NIP-46 round-trip needs a real
 * bunker. Covered by manual / E2E tests, not unit tests here.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import { hasNip07, createNip07Signer, Nip07Signer, EphemeralSigner, createLocalSignerFromNsec, LocalSigner, buildNostrConnectUri, DeferredBunkerSigner, type BunkerSignerImpl } from '../src/signers.js';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { nsecEncode } from 'nostr-tools/nip19';

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

describe('DeferredBunkerSigner', () => {
  const pubkey = 'b'.repeat(64);
  const authEvent = {
    id: 'a'.repeat(64), pubkey, kind: 21236 as const,
    created_at: 1, tags: [], content: '', sig: 'c'.repeat(128),
  };
  const signed = { id: 'e'.repeat(64), pubkey, kind: 1, created_at: 1, tags: [], content: 'hi', sig: 'f'.repeat(128) };
  const fakeBunker = {
    pubkey,
    signEvent: vi.fn(async () => signed),
    nip44: { encrypt: async (_p: string, _t: string) => 'CT', decrypt: async (_p: string, _c: string) => 'PT' },
    close: vi.fn(async () => {}),
  } as unknown as BunkerSignerImpl;

  it('exposes pubkey/method/signing capability up front', () => {
    const clientSecretKey = generateSecretKey();
    const bunkerUri = `bunker://${pubkey}?relay=wss://relay.example`;
    const s = new DeferredBunkerSigner(pubkey, authEvent, Promise.resolve(null), bunkerUri, clientSecretKey);
    expect(s.pubkey).toBe(pubkey);
    expect(s.method).toBe('bunker');
    expect(s.capabilities).toEqual({ canSignEvents: true, hasNip44: true });
    expect(s.bunkerUri).toBe(bunkerUri);
    expect(s.clientSecretKey).toBe(clientSecretKey);
  });

  it('delegates signEvent to the bunker once it connects', async () => {
    const s = new DeferredBunkerSigner(pubkey, authEvent, Promise.resolve(fakeBunker));
    await expect(s.signEvent({ kind: 1, content: 'hi', tags: [], created_at: 1 })).resolves.toEqual(signed);
  });

  it('delegates nip44 to the connected bunker', async () => {
    const s = new DeferredBunkerSigner(pubkey, authEvent, Promise.resolve(fakeBunker));
    expect(await s.nip44!.encrypt('peer', 'x')).toBe('CT');
    expect(await s.nip44!.decrypt('peer', 'y')).toBe('PT');
  });

  it('rejects signEvent with the auth-only error when the bunker never connected', async () => {
    const s = new DeferredBunkerSigner(pubkey, authEvent, Promise.resolve(null));
    await expect(s.signEvent({ kind: 1, content: '', tags: [], created_at: 1 })).rejects.toThrow(/signer-auth-only/);
  });

  it('close() is safe before and after the upgrade resolves', async () => {
    const s = new DeferredBunkerSigner(pubkey, authEvent, Promise.resolve(fakeBunker));
    await expect(s.close()).resolves.toBeUndefined();
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

describe('createLocalSignerFromNsec', () => {
  it('decodes a bech32 nsec and signs with the matching pubkey', async () => {
    const sk = generateSecretKey();
    const expectedPubkey = getPublicKey(sk);
    const nsec = nsecEncode(sk);

    const signer = createLocalSignerFromNsec(nsec);
    expect(signer).toBeInstanceOf(LocalSigner);
    expect(signer.pubkey).toBe(expectedPubkey);
    expect(signer.capabilities.canSignEvents).toBe(true);
    expect(signer.capabilities.hasNip44).toBe(true);

    const event = await signer.signEvent({ kind: 1, content: 'hi', tags: [], created_at: 1 });
    expect(event.pubkey).toBe(expectedPubkey);
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it('accepts a 64-char hex private key', () => {
    const sk = generateSecretKey();
    const hex = Array.from(sk, b => b.toString(16).padStart(2, '0')).join('');
    const signer = createLocalSignerFromNsec(hex);
    expect(signer.pubkey).toBe(getPublicKey(sk));
  });

  it('rejects empty input', () => {
    expect(() => createLocalSignerFromNsec('')).toThrow(/empty-nsec/);
    expect(() => createLocalSignerFromNsec('   ')).toThrow(/empty-nsec/);
  });

  it('rejects an npub (wrong prefix)', () => {
    expect(() => createLocalSignerFromNsec('npub1' + 'q'.repeat(58))).toThrow();
  });

  it('rejects garbage', () => {
    expect(() => createLocalSignerFromNsec('not-a-key')).toThrow(/invalid-nsec-format/);
  });

  it('zeros the privkey on close', async () => {
    const sk = generateSecretKey();
    const nsec = nsecEncode(sk);
    const signer = createLocalSignerFromNsec(nsec);
    await signer.close();
    // After close, signing fails — the schnorr lib rejects an all-zero key.
    await expect(
      signer.signEvent({ kind: 1, content: '', tags: [], created_at: 1 }),
    ).rejects.toThrow();
  });
});

describe('buildNostrConnectUri', () => {
  const validPubkey = 'a'.repeat(64);

  it('builds a well-formed nostrconnect:// URI', () => {
    const uri = buildNostrConnectUri({
      clientPubkeyHex: validPubkey,
      relayUrl: 'wss://relay.example.com',
      secret: 'abc123',
      perms: ['sign_event', 'nip44_encrypt'],
      appName: 'Test App',
    });
    expect(uri).toMatch(/^nostrconnect:\/\/[0-9a-f]{64}\?/);
    expect(uri).toContain(`nostrconnect://${validPubkey}?`);
    expect(uri).toContain('relay=wss%3A%2F%2Frelay.example.com');
    expect(uri).toContain('secret=abc123');
    expect(uri).toContain('perms=sign_event%2Cnip44_encrypt');
    expect(uri).toContain('name=Test+App');
  });

  it('omits perms and name when not provided', () => {
    const uri = buildNostrConnectUri({
      clientPubkeyHex: validPubkey,
      relayUrl: 'wss://r.example',
      secret: 's',
    });
    expect(uri).not.toContain('perms=');
    expect(uri).not.toContain('name=');
  });

  it('rejects invalid pubkey', () => {
    expect(() =>
      buildNostrConnectUri({ clientPubkeyHex: 'not-hex', relayUrl: 'wss://r', secret: 's' }),
    ).toThrow(/invalid-client-pubkey/);
  });

  it('rejects non-ws relay URLs', () => {
    expect(() =>
      buildNostrConnectUri({ clientPubkeyHex: validPubkey, relayUrl: 'http://r', secret: 's' }),
    ).toThrow(/invalid-relay-url/);
  });
});
