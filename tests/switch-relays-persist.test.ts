/**
 * A signer's `switch_relays` reply after connect moves the session to the
 * relays the signer keeps serving. The stored bunker URI must follow, so the
 * next restore reaches the signer; any reply that is not a usable relay list
 * (null, malformed, an error, no reply at all) must leave sign-in and the
 * stored URI exactly as they were.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type SwitchReply = { result: string } | { error: string } | 'silent';

const h = vi.hoisted(() => ({
  signerPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  switchReply: { result: 'null' } as { result: string } | { error: string } | 'silent',
  publishedMethods: [] as string[],
}));

vi.mock('nostr-tools/nip46', () => ({
  parseBunkerInput: async () => ({
    pubkey: h.signerPubkey,
    relays: ['wss://pairing.test'],
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
      let handlers: { onevent?: (event: unknown) => void } | undefined;
      return {
        subscribe: (_relays: string[], _filter: unknown, next: { onevent?: (event: unknown) => void }) => {
          handlers = next;
          return { close: () => {} };
        },
        publish: (_relays: string[], event: { pubkey: string; content: string }) => {
          queueMicrotask(() => {
            const conversationKey = getConversationKey(signerSecretKey, event.pubkey);
            const request = JSON.parse(decrypt(event.content, conversationKey)) as { id: string; method: string; params: string[] };
            h.publishedMethods.push(request.method);
            let body: { id: string; result?: string; error?: string };
            if (request.method === 'switch_relays') {
              if (h.switchReply === 'silent') return;
              body = { id: request.id, ...h.switchReply };
            } else {
              const result = request.method === 'get_public_key' ? h.signerPubkey
                : request.method === 'sign_event' ? JSON.stringify(finalizeEvent(JSON.parse(request.params[0]), signerSecretKey))
                : 'ack';
              body = { id: request.id, result };
            }
            handlers?.onevent?.(finalizeEvent({
              kind: NostrConnect,
              tags: [['p', event.pubkey]],
              content: encrypt(JSON.stringify(body), conversationKey),
              created_at: Math.floor(Date.now() / 1000),
            }, signerSecretKey));
          });
          return [Promise.resolve('ok')];
        },
        destroy: () => {},
      };
    }),
  };
});

import { bunkerUriWithRelays, createBunkerSigner } from '../src/signers.js';
import { handleRedirectCallback, restoreSession } from '../src/signet-login.js';
import { saveSessionToStorage, savePendingRedirect } from '../src/storage.js';
import { STORAGE_KEYS } from '../src/types.js';
import { callbackSearchForAuthEvent, makeAuthEvent } from './helpers/auth-event.js';

const SIGNER_SK = new Uint8Array(32);
SIGNER_SK[31] = 1;
const URI = `bunker://${h.signerPubkey}?relay=wss%3A%2F%2Fpairing.test&secret=sekret`;
const SWITCHED = `bunker://${h.signerPubkey}?relay=wss%3A%2F%2Fserve.test&secret=sekret`;
const ORIGIN = window.location.origin;
const CHALLENGE = 'c'.repeat(64);

const unchanged: Array<[string, SwitchReply]> = [
  ['null', { result: 'null' }],
  ['a non-array', { result: '"wss://serve.test"' }],
  ['an object', { result: '{}' }],
  ['an empty array', { result: '[]' }],
  ['a non-string entry', { result: '[1]' }],
  ['a non-relay URL', { result: '["https://serve.test"]' }],
  ['unparseable JSON', { result: 'not json' }],
  ['the same relays', { result: '["wss://pairing.test"]' }],
  ['an error', { error: 'unsupported-method:switch_relays' }],
];

function setLocation(search: string): void {
  window.history.replaceState(null, '', `/${search}`);
}

describe('switch_relays after bunker connect', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
    h.switchReply = { result: 'null' };
    h.publishedMethods = [];
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rewrites only the relays of a bunker URI', () => {
    expect(bunkerUriWithRelays(`${URI}&extra=1`, { pubkey: h.signerPubkey }, ['wss://a.test', 'wss://b.test']))
      .toBe(`bunker://${h.signerPubkey}?relay=wss%3A%2F%2Fa.test&relay=wss%3A%2F%2Fb.test&secret=sekret&extra=1`);
    expect(bunkerUriWithRelays('alice@example.com', { pubkey: h.signerPubkey, secret: 's' }, ['wss://a.test']))
      .toBe(`bunker://${h.signerPubkey}?relay=wss%3A%2F%2Fa.test&secret=s`);
  });

  it('carries a non-null reply into the reconnect URI and keeps the original bunkerUri', async () => {
    h.switchReply = { result: '["wss://serve.test"]' };
    const signer = await createBunkerSigner({ uri: URI });
    expect(h.publishedMethods).toEqual(['connect', 'get_public_key', 'switch_relays']);
    expect(signer.bunkerUri).toBe(URI);
    expect(signer.reconnectBunkerUri).toBe(SWITCHED);
    await signer.close();
  });

  it('keeps both relays when the signer names its serve relay and the pairing relay', async () => {
    h.switchReply = { result: '["wss://serve.test","wss://pairing.test"]' };
    const signer = await createBunkerSigner({ uri: URI });
    expect(signer.reconnectBunkerUri)
      .toBe(`bunker://${h.signerPubkey}?relay=wss%3A%2F%2Fserve.test&relay=wss%3A%2F%2Fpairing.test&secret=sekret`);
    await signer.close();
  });

  it.each(unchanged)('leaves the reconnect URI alone when the reply is %s', async (_label, reply) => {
    h.switchReply = reply;
    const signer = await createBunkerSigner({ uri: URI });
    expect(signer.reconnectBunkerUri).toBe(URI);
    await signer.close();
  });

  it('does not hold sign-in beyond the bound when the signer never answers', async () => {
    vi.useFakeTimers();
    h.switchReply = 'silent';
    const pending = createBunkerSigner({ uri: URI });
    await vi.advanceTimersByTimeAsync(1_001);
    const signer = await pending;
    expect(signer.reconnectBunkerUri).toBe(URI);
    await signer.close();
  });

  async function signInViaRedirect(): Promise<void> {
    const authEvent = makeAuthEvent({ privKey: SIGNER_SK, challenge: CHALLENGE, origin: ORIGIN });
    savePendingRedirect({ challenge: CHALLENGE, origin: ORIGIN, appName: 'Switch', createdAt: Date.now() });
    setLocation(callbackSearchForAuthEvent(authEvent, { bunker: URI }));
    const result = await handleRedirectCallback({ waitForBunker: true });
    expect(result.kind).toBe('session');
    if (result.kind === 'session') {
      expect(result.session.method).toBe('bunker');
      await result.session.signer.close?.();
    }
  }

  it('persists the switched relays at sign-in', async () => {
    h.switchReply = { result: '["wss://serve.test"]' };
    await signInViaRedirect();
    expect(localStorage.getItem(STORAGE_KEYS.bunkerUri)).toBe(SWITCHED);
  });

  it.each(unchanged)('persists the original URI at sign-in when the reply is %s', async (_label, reply) => {
    h.switchReply = reply;
    await signInViaRedirect();
    expect(localStorage.getItem(STORAGE_KEYS.bunkerUri)).toBe(URI);
  });

  async function storeSession(): Promise<void> {
    const authEvent = makeAuthEvent({ privKey: SIGNER_SK, challenge: CHALLENGE, origin: ORIGIN });
    await saveSessionToStorage({
      pubkey: authEvent.pubkey,
      method: 'bunker',
      authEventJson: JSON.stringify(authEvent),
      bunkerUri: URI,
      bunkerClientSkHex: '02'.repeat(32),
      displayName: 'Kept',
    });
  }

  it('updates only the stored bunker URI when a restored signer switches relays', async () => {
    await storeSession();
    h.switchReply = { result: '["wss://serve.test"]' };
    const restored = await restoreSession();
    expect(restored?.method).toBe('bunker');
    expect(localStorage.getItem(STORAGE_KEYS.bunkerUri)).toBe(SWITCHED);
    expect(localStorage.getItem(STORAGE_KEYS.displayName)).toBe('Kept');
    expect(localStorage.getItem(STORAGE_KEYS.bunkerClientSk)).toBe('02'.repeat(32));
    await restored?.signer.close?.();
  });

  it.each(unchanged)('restores without touching the stored URI when the reply is %s', async (_label, reply) => {
    await storeSession();
    h.switchReply = reply;
    const restored = await restoreSession();
    expect(restored?.method).toBe('bunker');
    expect(localStorage.getItem(STORAGE_KEYS.bunkerUri)).toBe(URI);
    await restored?.signer.close?.();
  });
});
