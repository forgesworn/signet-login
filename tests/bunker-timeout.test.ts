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
  publishedParams: [] as unknown[][],
  signingDelayMs: 0,
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
              const request = JSON.parse(decrypt(event.content, conversationKey)) as { id: string; method: string; params: unknown[] };
              h.publishedMethods.push(request.method);
              h.publishedParams.push(request.params);
              const result = request.method === 'get_public_key' ? h.signerPubkey
                : request.method === 'switch_relays' ? 'null'
                : request.method === 'sign_event' ? JSON.stringify(finalizeEvent(JSON.parse(request.params[0] as string), signerSecretKey)) : 'ack';
              const response = finalizeEvent({
                kind: NostrConnect,
                tags: [['p', event.pubkey]],
                content: encrypt(JSON.stringify({ id: request.id, result }), conversationKey),
                created_at: Math.floor(Date.now() / 1000),
              }, signerSecretKey);
              if (request.method === 'sign_event' && h.signingDelayMs) setTimeout(() => h.handlers?.onevent?.(response), h.signingDelayMs);
              else h.handlers?.onevent?.(response);
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
    h.publishedParams = [];
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


describe('bunker request deadlines and metadata', () => {
  beforeEach(() => { h.mode = 'respond'; h.publishedMethods = []; h.publishedParams = []; h.signingDelayMs = 0; });
  afterEach(() => { vi.useRealTimers(); });

  it('keeps the legacy connect wire shape when metadata is omitted', async () => {
    const signer = await createBunkerSigner({ uri: URI });
    expect(h.publishedParams[h.publishedMethods.indexOf('connect')]).toEqual([h.signerPubkey, 'sekret']);
    await signer.close();
  });

  it('sends optional name and URL in the connect metadata', async () => {
    const signer = await createBunkerSigner({ uri: URI, appName: 'Kindependence', appUrl: 'https://kindependence.example' });
    const params = h.publishedParams[h.publishedMethods.indexOf('connect')];
    expect(JSON.parse(params[2] as string)).toEqual({ name: 'Kindependence', url: 'https://kindependence.example' });
    await signer.close();
  });

  it('allows guardian signing beyond 15 seconds with an explicit request deadline', async () => {
    const signer = await createBunkerSigner({ uri: URI, requestTimeoutMs: 300_000 });
    vi.useFakeTimers();
    h.mode = 'hang';
    const pending = signer.signEvent({ kind: 30078, tags: [], content: '', created_at: Math.floor(Date.now() / 1000) });
    let settled = false;
    void pending.then(() => { settled = true; }, () => { settled = true; });
    const rejection = expect(pending).rejects.toThrow('nip46-sign_event-timeout');
    await vi.advanceTimersByTimeAsync(15_001);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(285_000);
    await rejection;
    await signer.close();
  });

  it('accepts a valid signature approved after the old 15-second deadline', async () => {
    const signer = await createBunkerSigner({ uri: URI, requestTimeoutMs: 300_000 });
    vi.useFakeTimers(); h.signingDelayMs = 20_000;
    const pending = signer.signEvent({ kind: 30078, tags: [], content: 'delayed approval' });
    await vi.advanceTimersByTimeAsync(20_001);
    expect(await pending).toMatchObject({ pubkey: h.signerPubkey, kind: 30078, content: 'delayed approval' });
    await signer.close();
  });

  it('still times out signing after 15 seconds for existing consumers', async () => {
    const signer = await createBunkerSigner({ uri: URI });
    vi.useFakeTimers(); h.mode = 'hang';
    const rejection = expect(signer.signEvent({ kind: 1, tags: [], content: '' })).rejects.toThrow('nip46-sign_event-timeout');
    await vi.advanceTimersByTimeAsync(15_001);
    await rejection; await signer.close();
  });

  it.each([0, -1, NaN, Infinity])('rejects an invalid request deadline %s', async value => {
    await expect(createBunkerSigner({ uri: URI, requestTimeoutMs: value })).rejects.toThrow('invalid-request-timeout');
  });
});
