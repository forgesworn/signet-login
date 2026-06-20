// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import WebSocket, { WebSocketServer } from 'ws';
import { NostrConnect } from 'nostr-tools/kinds';
import type { Event as NostrEvent, EventTemplate } from 'nostr-tools/core';
import type { Filter } from 'nostr-tools/filter';
import { decrypt, encrypt, getConversationKey } from 'nostr-tools/nip44';
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from 'nostr-tools/nip04';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';

import {
  buildNostrConnectUri,
  createBunkerSignerFromNostrConnect,
  createSessionFromSigner,
  restoreSession,
} from '../src/signet-login.js';
import {
  bytesToHexLocal,
  loadOrCreatePersistentClientSkFromStorage,
  saveSessionToStorage,
} from '../src/storage.js';
import type { NostrConnectStatus, SignetStorage } from '../src/types.js';

type RelayRequest = ['REQ', string, ...Filter[]];
type RelayEvent = ['EVENT', NostrEvent];
type RelayClose = ['CLOSE', string];
type RelayClientMessage = RelayRequest | RelayEvent | RelayClose;
type RelayServerMessage =
  | ['EVENT', string, NostrEvent]
  | ['EOSE', string]
  | ['OK', string, boolean, string];

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

function sendJson(ws: WebSocket, message: RelayServerMessage): void {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
}

function matchesFilter(filter: Filter, event: NostrEvent): boolean {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  if (filter.until !== undefined && event.created_at > filter.until) return false;
  for (const [key, value] of Object.entries(filter)) {
    if (!key.startsWith('#')) continue;
    if (!Array.isArray(value)) continue;
    const tagName = key.slice(1);
    if (!event.tags.some(([name, tagValue]) => name === tagName && value.includes(tagValue))) {
      return false;
    }
  }
  return true;
}

function matchesAnyFilter(filters: Filter[], event: NostrEvent): boolean {
  return filters.some(filter => matchesFilter(filter, event));
}

interface LocalNostrRelayOptions {
  dropLimitZeroLiveEvents?: boolean;
}

class LocalNostrRelay {
  private readonly clients = new Map<WebSocket, Map<string, Filter[]>>();
  private readonly waiters: Array<{
    predicate: (filters: Filter[]) => boolean;
    resolve: () => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  private constructor(
    private readonly server: WebSocketServer,
    public readonly url: string,
    private readonly options: LocalNostrRelayOptions = {},
  ) {}

  static async start(options: LocalNostrRelayOptions = {}): Promise<LocalNostrRelay> {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const address = server.address() as AddressInfo;
    const relay = new LocalNostrRelay(server, `ws://127.0.0.1:${address.port}`, options);
    server.on('connection', ws => relay.attach(ws));
    return relay;
  }

  waitForSubscription(predicate: (filters: Filter[]) => boolean, timeoutMs = 1_000): Promise<void> {
    for (const subscriptions of this.clients.values()) {
      for (const filters of subscriptions.values()) {
        if (predicate(filters)) return Promise.resolve();
      }
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        resolve: () => {
          clearTimeout(waiter.timer);
          this.removeWaiter(waiter);
          resolve();
        },
        reject: (err: Error) => {
          this.removeWaiter(waiter);
          reject(err);
        },
        timer: setTimeout(() => {
          waiter.reject(new Error('subscription-timeout'));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }

  async close(): Promise<void> {
    for (const waiter of [...this.waiters]) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error('relay-closed'));
    }
    for (const ws of this.clients.keys()) {
      ws.close();
    }
    await new Promise<void>(resolve => this.server.close(() => resolve()));
  }

  private attach(ws: WebSocket): void {
    this.clients.set(ws, new Map());
    ws.on('message', raw => this.handle(ws, raw.toString()));
    ws.on('close', () => this.clients.delete(ws));
  }

  private handle(ws: WebSocket, raw: string): void {
    let message: RelayClientMessage;
    try {
      message = JSON.parse(raw) as RelayClientMessage;
    } catch {
      return;
    }

    if (message[0] === 'REQ') {
      const [, subscriptionId, ...filters] = message;
      this.clients.get(ws)?.set(subscriptionId, filters);
      sendJson(ws, ['EOSE', subscriptionId]);
      this.notifySubscriptionWaiters(filters);
      return;
    }

    if (message[0] === 'CLOSE') {
      this.clients.get(ws)?.delete(message[1]);
      return;
    }

    if (message[0] === 'EVENT') {
      const event = message[1];
      sendJson(ws, ['OK', event.id, true, '']);
      this.broadcast(event);
    }
  }

  private broadcast(event: NostrEvent): void {
    for (const [ws, subscriptions] of this.clients.entries()) {
      for (const [subscriptionId, filters] of subscriptions.entries()) {
        const deliverableFilters = this.options.dropLimitZeroLiveEvents
          ? filters.filter(filter => filter.limit !== 0)
          : filters;
        if (matchesAnyFilter(deliverableFilters, event)) {
          sendJson(ws, ['EVENT', subscriptionId, event]);
        }
      }
    }
  }

  private notifySubscriptionWaiters(filters: Filter[]): void {
    for (const waiter of [...this.waiters]) {
      if (waiter.predicate(filters)) waiter.resolve();
    }
  }

  private removeWaiter(waiter: LocalNostrRelay['waiters'][number]): void {
    const index = this.waiters.indexOf(waiter);
    if (index >= 0) this.waiters.splice(index, 1);
  }
}

interface Nip46Request {
  id: string;
  method: string;
  params: string[];
}

class TestNip46Signer {
  readonly pubkey: string;
  connectRequests = 0;
  private readonly approvedClients = new Map<string, string>();
  private readonly okWaiters = new Map<string, { resolve: () => void; reject: (err: Error) => void }>();
  private ws?: WebSocket;

  constructor(
    private readonly relayUrl: string,
    private readonly secretKey: Uint8Array,
  ) {
    this.pubkey = getPublicKey(secretKey);
  }

  async start(): Promise<void> {
    const ws = new WebSocket(this.relayUrl);
    this.ws = ws;
    await once(ws, 'open');
    ws.on('message', raw => this.handleMessage(raw.toString()));
    ws.send(JSON.stringify(['REQ', 'nip46-requests', { kinds: [NostrConnect], '#p': [this.pubkey] }]));
  }

  async approveNostrConnect(uri: string): Promise<void> {
    const parsed = new URL(uri);
    const clientPubkey = parsed.hostname.toLowerCase();
    const secret = parsed.searchParams.get('secret');
    if (!/^[0-9a-f]{64}$/.test(clientPubkey)) throw new Error('invalid-client-pubkey');
    if (!secret) throw new Error('missing-secret');
    this.approvedClients.set(clientPubkey, secret);

    const content = encrypt(
      JSON.stringify({ result: secret }),
      getConversationKey(this.secretKey, clientPubkey),
    );
    await this.publish({
      kind: NostrConnect,
      tags: [['p', clientPubkey]],
      content,
      created_at: Math.floor(Date.now() / 1_000),
    });
  }

  async close(): Promise<void> {
    if (!this.ws || this.ws.readyState === WebSocket.CLOSED) return;
    this.ws.close();
    await once(this.ws, 'close').catch(() => {});
  }

  private async handleMessage(raw: string): Promise<void> {
    const message = JSON.parse(raw) as RelayServerMessage;
    if (message[0] === 'OK') {
      const waiter = this.okWaiters.get(message[1]);
      if (!waiter) return;
      this.okWaiters.delete(message[1]);
      if (message[2]) waiter.resolve();
      else waiter.reject(new Error(message[3]));
      return;
    }

    if (message[0] !== 'EVENT') return;
    const event = message[2];
    const conversationKey = getConversationKey(this.secretKey, event.pubkey);
    const request = JSON.parse(decrypt(event.content, conversationKey)) as Nip46Request;
    const response = await this.handleRequest(event.pubkey, request);
    const content = encrypt(JSON.stringify(response), conversationKey);
    await this.publish({
      kind: NostrConnect,
      tags: [['p', event.pubkey]],
      content,
      created_at: Math.floor(Date.now() / 1_000),
    });
  }

  private async handleRequest(clientPubkey: string, request: Nip46Request): Promise<{ id: string; result?: string; error?: string }> {
    try {
      switch (request.method) {
        case 'connect': {
          this.connectRequests++;
          const expectedSecret = this.approvedClients.get(clientPubkey);
          if (expectedSecret && request.params[1] !== expectedSecret) {
            return { id: request.id, error: 'secret-mismatch' };
          }
          return { id: request.id, result: 'ack' };
        }
        case 'get_public_key':
          return { id: request.id, result: this.pubkey };
        case 'switch_relays':
          return { id: request.id, result: JSON.stringify([this.relayUrl]) };
        case 'ping':
          return { id: request.id, result: 'pong' };
        case 'sign_event': {
          const template = JSON.parse(request.params[0]) as EventTemplate;
          const signed = finalizeEvent(template, this.secretKey);
          return { id: request.id, result: JSON.stringify(signed) };
        }
        case 'nip44_encrypt': {
          const [peerPubkey, plaintext] = request.params;
          return { id: request.id, result: encrypt(plaintext, getConversationKey(this.secretKey, peerPubkey)) };
        }
        case 'nip44_decrypt': {
          const [peerPubkey, ciphertext] = request.params;
          return { id: request.id, result: decrypt(ciphertext, getConversationKey(this.secretKey, peerPubkey)) };
        }
        case 'nip04_encrypt': {
          const [peerPubkey, plaintext] = request.params;
          return { id: request.id, result: nip04Encrypt(this.secretKey, peerPubkey, plaintext) };
        }
        case 'nip04_decrypt': {
          const [peerPubkey, ciphertext] = request.params;
          return { id: request.id, result: nip04Decrypt(this.secretKey, peerPubkey, ciphertext) };
        }
        case 'logout':
          return { id: request.id, result: 'ack' };
        default:
          return { id: request.id, error: `unsupported-method:${request.method}` };
      }
    } catch (err) {
      return { id: request.id, error: err instanceof Error ? err.message : String(err) };
    }
  }

  private async publish(template: EventTemplate): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('signer-not-connected');
    const event = finalizeEvent(template, this.secretKey);
    const ack = new Promise<void>((resolve, reject) => {
      this.okWaiters.set(event.id, { resolve, reject });
      setTimeout(() => {
        if (!this.okWaiters.has(event.id)) return;
        this.okWaiters.delete(event.id);
        reject(new Error('publish-timeout'));
      }, 1_000);
    });
    this.ws.send(JSON.stringify(['EVENT', event]));
    await ack;
  }
}

describe('NIP-46 NostrConnect restore E2E', () => {
  let relay: LocalNostrRelay | undefined;
  let testSigner: TestNip46Signer | undefined;

  afterEach(async () => {
    await testSigner?.close();
    await relay?.close();
    testSigner = undefined;
    relay = undefined;
  });

  it('pairs with nostrconnect:// once, persists bunker://, and restores signing plus NIP-44 without limit-zero live delivery', async () => {
    relay = await LocalNostrRelay.start({ dropLimitZeroLiveEvents: true });
    testSigner = new TestNip46Signer(relay.url, generateSecretKey());
    await testSigner.start();

    const storage = memoryStorage();
    const clientSecretKey = await loadOrCreatePersistentClientSkFromStorage(storage);
    const clientPubkey = getPublicKey(clientSecretKey);
    const uri = buildNostrConnectUri({
      clientPubkeyHex: clientPubkey,
      relayUrl: relay.url,
      secret: 'restore-pair-secret',
      perms: ['sign_event', 'nip44_encrypt', 'nip44_decrypt'],
      appName: 'Restore E2E',
      appUrl: 'https://restore.example',
    });

    const pairing = createBunkerSignerFromNostrConnect({ uri, clientSecretKey });
    await relay.waitForSubscription(filters =>
      filters.some(filter =>
        filter.kinds?.includes(NostrConnect)
        && filter['#p']?.includes(clientPubkey)
        && filter.limit !== 0,
      ),
    );
    await testSigner.approveNostrConnect(uri);

    const pairedSigner = await pairing;
    expect(pairedSigner.pubkey).toBe(testSigner.pubkey);
    expect(pairedSigner.bunkerUri).toMatch(new RegExp(`^bunker://${testSigner.pubkey}\\?`));
    expect(new URL(pairedSigner.bunkerUri).searchParams.get('relay')).toBe(relay.url);
    expect(new URL(pairedSigner.bunkerUri).searchParams.get('secret')).toBe('restore-pair-secret');

    const session = await createSessionFromSigner(pairedSigner, {
      appName: 'Restore E2E',
      challenge: 'ab'.repeat(32),
      origin: 'https://restore.example',
    });
    await saveSessionToStorage({
      pubkey: session.pubkey,
      method: session.method,
      authEventJson: JSON.stringify(session.authEvent),
      bunkerUri: pairedSigner.bunkerUri,
      bunkerClientSkHex: bytesToHexLocal(pairedSigner.clientSecretKey),
    }, storage);
    await pairedSigner.close();

    const restoreStatuses: NostrConnectStatus[] = [];
    const restored = await restoreSession({
      storage,
      onNostrConnectStatus: event => restoreStatuses.push(event),
    });
    expect(restored?.pubkey).toBe(testSigner.pubkey);
    expect(restored?.method).toBe('bunker');
    expect(restored?.signer.capabilities).toEqual({ canSignEvents: true, hasNip44: true });
    expect(testSigner.connectRequests).toBe(1);
    expect(restoreStatuses).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'request-sent', method: 'connect' }),
      expect.objectContaining({ type: 'response-received', method: 'connect' }),
    ]));

    const signed = await restored!.signer.signEvent({
      kind: 1,
      content: 'restored signer works',
      tags: [],
      created_at: 1_700_000_000,
    });
    expect(signed.pubkey).toBe(testSigner.pubkey);
    expect(signed.kind).toBe(1);

    const ciphertext = await restored!.signer.nip44!.encrypt(testSigner.pubkey, 'restored-nip44-secret');
    expect(ciphertext).not.toBe('restored-nip44-secret');
    await expect(restored!.signer.nip44!.decrypt(testSigner.pubkey, ciphertext)).resolves.toBe('restored-nip44-secret');

    const peerSk = generateSecretKey();
    const peerPubkey = getPublicKey(peerSk);
    const nip04Ciphertext = await restored!.signer.nip04!.encrypt(peerPubkey, 'restored-nip04-secret');
    expect(nip04Ciphertext).not.toBe('restored-nip04-secret');
    expect(nip04Decrypt(peerSk, testSigner.pubkey, nip04Ciphertext)).toBe('restored-nip04-secret');
    const incomingNip04Ciphertext = nip04Encrypt(peerSk, testSigner.pubkey, 'incoming-nip04-secret');
    await expect(restored!.signer.nip04!.decrypt(peerPubkey, incomingNip04Ciphertext)).resolves.toBe('incoming-nip04-secret');

    await expect(restored!.signer.nip46!.ping()).resolves.toBeUndefined();
    await expect(restored!.signer.nip46!.switchRelays()).resolves.toBe(false);
    await expect(restored!.signer.nip46!.logout()).resolves.toBeUndefined();

    await restored!.signer.close();
  });

  it('pairs when the relay does not deliver live events to limit-zero subscriptions', async () => {
    relay = await LocalNostrRelay.start({ dropLimitZeroLiveEvents: true });
    testSigner = new TestNip46Signer(relay.url, generateSecretKey());
    await testSigner.start();

    const storage = memoryStorage();
    const clientSecretKey = await loadOrCreatePersistentClientSkFromStorage(storage);
    const clientPubkey = getPublicKey(clientSecretKey);
    const uri = buildNostrConnectUri({
      clientPubkeyHex: clientPubkey,
      relayUrl: relay.url,
      secret: 'limit-zero-pair-secret',
      perms: ['sign_event', 'nip44_encrypt', 'nip44_decrypt'],
      appName: 'Limit Zero E2E',
      appUrl: 'https://limit-zero.example',
    });

    const pairing = createBunkerSignerFromNostrConnect({ uri, clientSecretKey });
    await relay.waitForSubscription(filters =>
      filters.some(filter =>
        filter.kinds?.includes(NostrConnect)
        && filter['#p']?.includes(clientPubkey)
        && filter.limit !== 0,
      ),
    );
    await testSigner.approveNostrConnect(uri);

    const pairedSigner = await pairing;
    expect(pairedSigner.pubkey).toBe(testSigner.pubkey);

    const signed = await pairedSigner.signEvent({
      kind: 1,
      content: 'hello from robust nostrconnect',
      tags: [],
      created_at: Math.floor(Date.now() / 1000),
    });
    expect(signed.pubkey).toBe(testSigner.pubkey);
    await pairedSigner.close();
  });
});
