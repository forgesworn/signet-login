import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NostrConnectStatus } from '../src/types.js';

const h = vi.hoisted(() => {
  const signerSecretKey = new Uint8Array(32);
  signerSecretKey[31] = 1;
  return {
    signerSecretKey,
    signerPubkey: '',
    connection: 'success' as 'success' | 'fail',
    mode: 'respond' as 'respond' | 'hang',
    subscriptions: [] as Array<{
      relays: string[];
      handlers: {
        onevent?: (event: unknown) => void;
        onclose?: (reasons?: string[]) => void;
      };
    }>,
    closeReasons: [] as string[],
    destroys: 0,
    publishedMethods: [] as string[],
  };
});

vi.mock('nostr-tools/pool', async () => {
  const { encrypt, decrypt, getConversationKey } = await import('nostr-tools/nip44');
  const { finalizeEvent } = await import('nostr-tools/pure');
  const { NostrConnect } = await import('nostr-tools/kinds');

  return {
    SimplePool: vi.fn().mockImplementation(function (options?: {
      onRelayConnectionFailure?: (url: string) => void;
      onRelayConnectionSuccess?: (url: string) => void;
    }) {
      return {
      subscribe: (relays: string[], _filter: unknown, handlers: { onevent?: (event: unknown) => void; onclose?: (reasons?: string[]) => void }) => {
        h.subscriptions.push({ relays, handlers });
        if (h.connection === 'fail') options?.onRelayConnectionFailure?.(relays[0]);
        else options?.onRelayConnectionSuccess?.(relays[0]);
        return {
          close: (reason?: string) => {
            h.closeReasons.push(reason ?? '');
          },
        };
      },
      publish: (_relays: string[], event: { pubkey: string; content: string }) => {
        if (h.mode === 'respond') {
          queueMicrotask(() => {
            const conversationKey = getConversationKey(h.signerSecretKey, event.pubkey);
            const request = JSON.parse(decrypt(event.content, conversationKey)) as {
              id: string;
              method: string;
              params: string[];
            };
            h.publishedMethods.push(request.method);
            let result = 'ack';
            if (request.method === 'get_public_key') {
              result = h.signerPubkey;
            } else if (request.method === 'sign_event') {
              result = JSON.stringify(finalizeEvent(JSON.parse(request.params[0]), h.signerSecretKey));
            }
            const response = finalizeEvent({
              kind: NostrConnect,
              tags: [['p', event.pubkey]],
              content: encrypt(JSON.stringify({ id: request.id, result }), conversationKey),
              created_at: Math.floor(Date.now() / 1000),
            }, h.signerSecretKey);
            h.subscriptions.at(-1)?.handlers.onevent?.(response);
          });
        }
        return [Promise.resolve('ok')];
      },
      destroy: () => {
        h.destroys += 1;
      },
    };
    }),
  };
});

import { encrypt, getConversationKey } from 'nostr-tools/nip44';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { NostrConnect } from 'nostr-tools/kinds';
import {
  buildNostrConnectUri,
  createBunkerSignerFromNostrConnect,
} from '../src/signers.js';

function clientSecretKey(): Uint8Array {
  const key = new Uint8Array(32);
  key[31] = 2;
  return key;
}

function pairingUri(clientKey: Uint8Array): string {
  return buildNostrConnectUri({
    clientPubkeyHex: getPublicKey(clientKey),
    relayUrl: 'wss://relay.test',
    secret: 'status-secret',
    perms: ['sign_event', 'nip04_encrypt', 'nip04_decrypt', 'nip44_encrypt', 'nip44_decrypt'],
    appName: 'Status Test',
    appUrl: 'https://status.example',
  });
}

function approvePairing(uri: string, clientKey: Uint8Array): void {
  const clientPubkey = getPublicKey(clientKey);
  const secret = new URL(uri).searchParams.get('secret');
  const event = finalizeEvent({
    kind: NostrConnect,
    tags: [['p', clientPubkey]],
    content: encrypt(
      JSON.stringify({ result: secret }),
      getConversationKey(h.signerSecretKey, clientPubkey),
    ),
    created_at: Math.floor(Date.now() / 1000),
  }, h.signerSecretKey);
  h.subscriptions[0]?.handlers.onevent?.(event);
}

describe('NostrConnect status events', () => {
  beforeEach(() => {
    h.signerPubkey = getPublicKey(h.signerSecretKey);
    h.connection = 'success';
    h.mode = 'respond';
    h.subscriptions = [];
    h.closeReasons = [];
    h.destroys = 0;
    h.publishedMethods = [];
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('reports pairing, request, and response progress', async () => {
    const key = clientSecretKey();
    const uri = pairingUri(key);
    const events: NostrConnectStatus[] = [];

    const pending = createBunkerSignerFromNostrConnect({
      uri,
      clientSecretKey: key,
      timeoutMs: 5_000,
      onStatus: event => events.push(event),
    });
    approvePairing(uri, key);
    const signer = await pending;

    expect(signer.pubkey).toBe(h.signerPubkey);
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'uri-created', uri, timeoutMs: 5_000 }),
      expect.objectContaining({ type: 'relay-connecting' }),
      expect.objectContaining({ type: 'relay-connected', relay: 'wss://relay.test' }),
      expect.objectContaining({ type: 'signer-seen', signerPubkey: h.signerPubkey }),
      expect.objectContaining({ type: 'response-received', phase: 'pairing', signerPubkey: h.signerPubkey }),
    ]));

    const signed = await signer.signEvent({
      kind: 1,
      content: 'status events keep working after pairing',
      tags: [],
      created_at: 1_700_000_000,
    });
    expect(signed.pubkey).toBe(h.signerPubkey);
    expect(h.publishedMethods).toContain('sign_event');
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'request-sent', method: 'sign_event' }),
      expect.objectContaining({ type: 'response-received', method: 'sign_event' }),
    ]));
    expect(events.filter(event => event.type === 'error')).toEqual([]);
    await signer.close();
  });

  it('reports the configured pairing timeout', async () => {
    vi.useFakeTimers();
    h.mode = 'hang';
    const key = clientSecretKey();
    const events: NostrConnectStatus[] = [];

    const pending = createBunkerSignerFromNostrConnect({
      uri: pairingUri(key),
      clientSecretKey: key,
      timeoutMs: 30,
      onStatus: event => events.push(event),
    });
    const rejection = expect(pending).rejects.toThrow('nostrconnect-timeout');

    await vi.advanceTimersByTimeAsync(31);

    await rejection;
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        type: 'timeout',
        phase: 'pairing',
        timeoutMs: 30,
        message: 'nostrconnect-timeout',
      }),
    ]));
  });

  it('closes the RobustBunkerClient if getPublicKey fails after pairing succeeds', async () => {
    vi.useFakeTimers();
    // 'hang' means no request published after pairing gets an automatic
    // response — the get_public_key call below will time out internally.
    h.mode = 'hang';
    const key = clientSecretKey();
    const uri = pairingUri(key);

    const pending = createBunkerSignerFromNostrConnect({
      uri,
      clientSecretKey: key,
      timeoutMs: 5_000,
    });
    // Attach the rejection expectation before advancing fake timers so the
    // eventual rejection is never briefly unhandled.
    const rejection = expect(pending).rejects.toThrow('nip46-get_public_key-timeout');

    approvePairing(uri, key);
    // Flush the microtask that carries pairing success into the
    // RobustBunkerClient construction + getPublicKey() call.
    await vi.advanceTimersByTimeAsync(0);

    // Past the 15s NIP-46 request timeout for get_public_key.
    await vi.advanceTimersByTimeAsync(15_001);

    await rejection;

    // The RobustBunkerClient (its SimplePool + subscription) must be closed
    // on this failure path, not leaked.
    expect(h.closeReasons).toContain('closed by caller');
    expect(h.destroys).toBeGreaterThanOrEqual(2); // pairing pool + bunker pool
  });

  it('reports relay connection failures separately from pairing cancellation', async () => {
    h.connection = 'fail';
    const key = clientSecretKey();
    const events: NostrConnectStatus[] = [];
    const ac = new AbortController();

    const pending = createBunkerSignerFromNostrConnect({
      uri: pairingUri(key),
      clientSecretKey: key,
      abortSignal: ac.signal,
      onStatus: event => events.push(event),
    });
    ac.abort();

    await expect(pending).rejects.toThrow('nostrconnect-aborted');
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        type: 'error',
        phase: 'relay',
        relay: 'wss://relay.test',
        message: 'relay-connection-failed',
      }),
      expect.objectContaining({
        type: 'error',
        phase: 'abort',
        message: 'nostrconnect-aborted',
      }),
    ]));
  });
});
