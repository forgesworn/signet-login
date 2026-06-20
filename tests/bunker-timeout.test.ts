/**
 * Regression tests for the createBunkerSigner handshake guard.
 *
 * The implementation now uses Signet's relay-compatible NIP-46 client for both
 * nostrconnect:// pairing and bunker:// restore. These tests mock the relay pool
 * directly so we can prove timeout and success behavior without opening sockets.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  signerPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  mode: 'hang' as 'hang' | 'respond',
  destroy: vi.fn(),
  subClose: vi.fn(),
  handlers: undefined as undefined | { onevent?: (event: unknown) => void },
  publishedMethods: [] as string[],
}));

vi.mock('nostr-tools/nip46', () => ({
  parseBunkerInput: async () => ({
    pubkey: h.signerPubkey,
    relays: ['wss://relay.test'],
    secret: 'sekret',
  }),
}));

vi.mock('nostr-tools/pool', async () => {
  const { encrypt, decrypt, getConversationKey } = await import('nostr-tools/nip44');
  const { finalizeEvent } = await import('nostr-tools/pure');
  const { NostrConnect } = await import('nostr-tools/kinds');
  const signerSecretKey = new Uint8Array(32);
  signerSecretKey[31] = 1;

  return {
    SimplePool: vi.fn().mockImplementation(function () {
      return {
        subscribe: (_relays: string[], _filter: unknown, handlers: { onevent?: (event: unknown) => void }) => {
          h.handlers = handlers;
          return { close: h.subClose };
        },
        publish: (_relays: string[], event: { pubkey: string; content: string }) => {
          if (h.mode === 'respond') {
            queueMicrotask(() => {
              const conversationKey = getConversationKey(signerSecretKey, event.pubkey);
              const request = JSON.parse(decrypt(event.content, conversationKey)) as { id: string; method: string };
              h.publishedMethods.push(request.method);
              const result = request.method === 'get_public_key' ? h.signerPubkey : 'ack';
              const response = finalizeEvent({
                kind: NostrConnect,
                tags: [['p', event.pubkey]],
                content: encrypt(JSON.stringify({ id: request.id, result }), conversationKey),
                created_at: Math.floor(Date.now() / 1000),
              }, signerSecretKey);
              h.handlers?.onevent?.(response);
            });
          }
          return [Promise.resolve('ok')];
        },
        destroy: h.destroy,
      };
    }),
  };
});

import { createBunkerSigner } from '../src/signers.js';

const URI = `bunker://${h.signerPubkey}?relay=wss://relay.test&secret=sekret`;

describe('createBunkerSigner timeout guard', () => {
  beforeEach(() => {
    h.mode = 'hang';
    h.destroy.mockClear();
    h.subClose.mockClear();
    h.handlers = undefined;
    h.publishedMethods = [];
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects with bunker-connect-timeout and closes the signer when the explicit deadline wins', async () => {
    vi.useFakeTimers();
    const pending = createBunkerSigner({ uri: URI, timeoutMs: 30 });
    const rejection = expect(pending).rejects.toThrow('bunker-connect-timeout');

    await vi.advanceTimersByTimeAsync(31);

    await rejection;
    expect(h.subClose).toHaveBeenCalled();
    expect(h.destroy).toHaveBeenCalled();
  });

  it('resolves normally when the connect response arrives before the explicit deadline', async () => {
    h.mode = 'respond';

    const signer = await createBunkerSigner({ uri: URI, timeoutMs: 1_000 });

    expect(signer.pubkey).toBe(h.signerPubkey);
    expect(h.publishedMethods).toContain('connect');
    expect(h.destroy).not.toHaveBeenCalled();
    await signer.close();
  });

  it('uses the built-in NIP-46 request timeout when timeoutMs is omitted', async () => {
    vi.useFakeTimers();
    const pending = createBunkerSigner({ uri: URI });
    const rejection = expect(pending).rejects.toThrow('nip46-connect-timeout');

    await vi.advanceTimersByTimeAsync(15_001);

    await rejection;
    expect(h.subClose).toHaveBeenCalled();
    expect(h.destroy).toHaveBeenCalled();
  });
});
