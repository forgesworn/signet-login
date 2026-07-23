/**
 * Three signer implementations behind one interface.
 *
 *   Nip07Signer       — wraps window.nostr (bark, Alby, nos2x, Flamingo, …)
 *   BunkerSignerImpl  — wraps nostr-tools BunkerSigner (NIP-46 over relay)
 *   EphemeralSigner   — auth-only fallback when only the redirect signature is available
 */

import type {
  EventTemplate,
  NostrConnectStatus,
  NostrConnectStatusHandler,
  NostrEvent,
  SignetAuthEvent,
  SignetSigner,
  SignerCapabilities,
} from './types.js';
import { parseBunkerInput, type BunkerPointer } from 'nostr-tools/nip46';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { NostrConnect } from 'nostr-tools/kinds';
import { SimplePool } from 'nostr-tools/pool';
import type { SubCloser } from 'nostr-tools/abstract-pool';
import { decode as nip19Decode } from 'nostr-tools/nip19';
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44';
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from 'nostr-tools/nip04';

// ── NIP-07 ────────────────────────────────────────────────────────────────────

/** The shape of `window.nostr` exposed by NIP-07 extensions. */
interface Nip07Provider {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<NostrEvent>;
  nip04?: {
    encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  };
  nip44?: {
    encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  };
}

declare global {
  interface Window {
    nostr?: Nip07Provider;
  }
}

/** Returns true if a NIP-07 extension is present on the page. */
export function hasNip07(): boolean {
  return typeof window !== 'undefined' && !!window.nostr && typeof window.nostr.signEvent === 'function';
}

export class Nip07Signer implements SignetSigner {
  readonly method = 'nip07' as const;
  readonly capabilities: SignerCapabilities;
  readonly nip04?: SignetSigner['nip04'];
  readonly nip44?: SignetSigner['nip44'];

  constructor(public readonly pubkey: string, private readonly provider: Nip07Provider) {
    this.capabilities = { canSignEvents: true, hasNip44: !!provider.nip44 };
    if (provider.nip04) {
      this.nip04 = {
        encrypt: (peer, pt) => provider.nip04!.encrypt(peer, pt),
        decrypt: (peer, ct) => provider.nip04!.decrypt(peer, ct),
      };
    }
    if (provider.nip44) {
      this.nip44 = {
        encrypt: (peer, pt) => provider.nip44!.encrypt(peer, pt),
        decrypt: (peer, ct) => provider.nip44!.decrypt(peer, ct),
      };
    }
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    // NIP-07 requires a complete unsigned event. SignetSigner intentionally
    // accepts lightweight templates, so normalise at the provider boundary
    // for strict extensions such as Ditto (and preserve caller-supplied
    // values when they are present).
    const filled: Required<EventTemplate> = {
      kind: template.kind,
      content: template.content,
      created_at: template.created_at ?? Math.floor(Date.now() / 1000),
      tags: template.tags ?? [],
    };
    return retryTransientNip07Sign(() => this.provider.signEvent(filled));
  }

  async close(): Promise<void> {
    // NIP-07 extensions have no concept of disconnect — nothing to do.
  }
}

async function retryTransientNip07Sign(sign: () => Promise<NostrEvent>): Promise<NostrEvent> {
  try {
    return await sign();
  } catch (err) {
    if (!isTransientNip07Error(err)) throw err;
    await new Promise(resolve => setTimeout(resolve, 250));
    return sign();
  }
}

function isTransientNip07Error(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /Request failed|Receiving end does not exist|Extension context invalidated|message port closed|context invalidated/i.test(msg);
}

/** Connects to the page's NIP-07 provider and returns a Nip07Signer. */
export async function createNip07Signer(): Promise<Nip07Signer> {
  if (!hasNip07()) throw new Error('no-nip07-provider');
  const provider = window.nostr!;
  const pubkey = await provider.getPublicKey();
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('invalid-pubkey-from-nip07');
  return new Nip07Signer(pubkey.toLowerCase(), provider);
}

// ── NIP-46 bunker ─────────────────────────────────────────────────────────────

interface Nip46SignerClient {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<NostrEvent>;
  nip04Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip04Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  ping(): Promise<void>;
  switchRelays(): Promise<boolean>;
  logout(): Promise<void>;
  close(): Promise<void>;
}

/** Wraps a NIP-46 client with our SignetSigner interface. */
export class BunkerSignerImpl implements SignetSigner {
  readonly method = 'bunker' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: true, hasNip44: true };
  readonly nip04: SignetSigner['nip04'];
  readonly nip44: SignetSigner['nip44'];
  readonly nip46: SignetSigner['nip46'];

  constructor(
    public readonly pubkey: string,
    private readonly bunker: Nip46SignerClient,
    /** Original bunker URI — kept for persistence/reconnect. */
    public readonly bunkerUri: string,
    /** The 32-byte client secret key used in this session — kept for reconnect. */
    public readonly clientSecretKey: Uint8Array,
  ) {
    this.nip04 = {
      encrypt: (peer, pt) => bunker.nip04Encrypt(peer, pt),
      decrypt: (peer, ct) => bunker.nip04Decrypt(peer, ct),
    };
    this.nip44 = {
      encrypt: (peer, pt) => bunker.nip44Encrypt(peer, pt),
      decrypt: (peer, ct) => bunker.nip44Decrypt(peer, ct),
    };
    this.nip46 = {
      ping: () => bunker.ping(),
      switchRelays: () => bunker.switchRelays(),
      logout: () => bunker.logout(),
    };
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    // Build the event for the bunker to sign. SET pubkey to the signer's own key
    // rather than stripping it: some signers (e.g. Signet mobile) sign the event
    // as-given and don't fill pubkey themselves, returning `pubkey:""` — which
    // then fails verifyEvent ("event returned from bunker is improperly signed").
    // Providing the key-owner's own pubkey is correct NIP-01 construction and is
    // harmless to bunkers that set it themselves (it's the same value).
    const { pubkey: _omit, ...rest } = template as EventTemplate & { pubkey?: string };
    void _omit;
    const filled = {
      pubkey: this.pubkey,
      kind: rest.kind,
      content: rest.content,
      created_at: rest.created_at ?? Math.floor(Date.now() / 1000),
      tags: rest.tags ?? [],
    };
    const verified = await this.bunker.signEvent(filled);
    return verified as NostrEvent;
  }

  async close(): Promise<void> {
    await this.bunker.close();
  }
}

const NIP46_PAIRING_WAIT_MS = 5 * 60_000;
const NIP46_REQUEST_TIMEOUT_MS = 15_000;

interface SimplePoolOptionsWithStatus {
  enablePing?: boolean;
  enableReconnect?: boolean;
  onRelayConnectionFailure?: (url: string) => void;
  onRelayConnectionSuccess?: (url: string) => void;
}

interface Nip46Response {
  id?: string;
  result?: string;
  error?: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function emitNostrConnectStatus(
  onStatus: NostrConnectStatusHandler | undefined,
  relays: readonly string[],
  status: Omit<NostrConnectStatus, 'timestamp' | 'relays'>,
): void {
  if (!onStatus) return;
  try {
    onStatus({
      ...status,
      timestamp: Date.now(),
      relays: [...relays],
    });
  } catch {
    // Consumer diagnostics must never break the login flow.
  }
}

function createInstrumentedNostrConnectPool(input: {
  relays: readonly string[];
  onStatus?: NostrConnectStatusHandler;
  clientPubkey?: string;
  signerPubkey?: string;
}): SimplePool {
  const poolOptions: SimplePoolOptionsWithStatus = {
    enableReconnect: true,
    onRelayConnectionSuccess: relay => {
      emitNostrConnectStatus(input.onStatus, input.relays, {
        type: 'relay-connected',
        relay,
        clientPubkey: input.clientPubkey,
        signerPubkey: input.signerPubkey,
      });
    },
    onRelayConnectionFailure: relay => {
      emitNostrConnectStatus(input.onStatus, input.relays, {
        type: 'error',
        phase: 'relay',
        relay,
        clientPubkey: input.clientPubkey,
        signerPubkey: input.signerPubkey,
        message: 'relay-connection-failed',
      });
    },
  };
  return new SimplePool(poolOptions);
}

function firstFulfilled<T>(promises: Promise<T>[]): Promise<T> {
  if (promises.length === 0) return Promise.reject(new Error('no-promises'));
  return new Promise((resolve, reject) => {
    let rejected = 0;
    let lastError: unknown;
    for (const promise of promises) {
      promise.then(resolve).catch(err => {
        rejected += 1;
        lastError = err;
        if (rejected === promises.length) {
          reject(lastError instanceof Error ? lastError : new Error(String(lastError)));
        }
      });
    }
  });
}

function parseNostrConnectUriForClient(uri: string, clientPubkey: string): {
  relays: string[];
  secret: string;
} {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error('invalid-nostrconnect-uri');
  }
  if (parsed.protocol !== 'nostrconnect:') throw new Error('invalid-nostrconnect-uri');
  if (parsed.hostname.toLowerCase() !== clientPubkey.toLowerCase()) throw new Error('nostrconnect-client-pubkey-mismatch');
  const relays = parsed.searchParams.getAll('relay').map(relay => relay.trim()).filter(Boolean);
  if (relays.length === 0) throw new Error('relay-url-required');
  for (const relayUrl of relays) {
    if (!/^wss?:\/\//.test(relayUrl)) throw new Error('invalid-relay-url');
  }
  const secret = parsed.searchParams.get('secret');
  if (!secret) throw new Error('nostrconnect-secret-required');
  return {
    relays: Array.from(new Set(relays)),
    secret,
  };
}

async function waitForNostrConnectApproval(input: {
  uri: string;
  clientSecretKey: Uint8Array;
  abortSignal?: AbortSignal;
  timeoutMs?: number;
  onStatus?: NostrConnectStatusHandler;
}): Promise<{ signerPubkey: string; relays: string[]; secret: string }> {
  const clientPubkey = getPublicKey(input.clientSecretKey);
  const { relays, secret } = parseNostrConnectUriForClient(input.uri, clientPubkey);
  const timeoutMs = input.timeoutMs && input.timeoutMs > 0 ? input.timeoutMs : NIP46_PAIRING_WAIT_MS;
  emitNostrConnectStatus(input.onStatus, relays, {
    type: 'uri-created',
    uri: input.uri,
    clientPubkey,
    timeoutMs,
  });
  emitNostrConnectStatus(input.onStatus, relays, {
    type: 'relay-connecting',
    clientPubkey,
    timeoutMs,
  });
  const pool = createInstrumentedNostrConnectPool({
    relays,
    onStatus: input.onStatus,
    clientPubkey,
  });
  let sub: SubCloser | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err: Error | null, signerPubkey?: string): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      sub?.close(err ? 'nostrconnect-failed' : 'nostrconnect-paired');
      pool.destroy();
      if (err) {
        const message = errorMessage(err);
        if (message === 'nostrconnect-timeout') {
          emitNostrConnectStatus(input.onStatus, relays, {
            type: 'timeout',
            phase: 'pairing',
            clientPubkey,
            timeoutMs,
            message,
            error: err,
          });
        } else {
          emitNostrConnectStatus(input.onStatus, relays, {
            type: 'error',
            phase: message === 'nostrconnect-aborted' ? 'abort' : 'pairing',
            clientPubkey,
            message,
            error: err,
          });
        }
        reject(err);
      } else {
        resolve({ signerPubkey: signerPubkey!.toLowerCase(), relays, secret });
      }
    };

    if (input.abortSignal?.aborted) {
      finish(new Error('nostrconnect-aborted'));
      return;
    }
    input.abortSignal?.addEventListener('abort', () => finish(new Error('nostrconnect-aborted')), { once: true });
    timer = setTimeout(() => finish(new Error('nostrconnect-timeout')), timeoutMs);

    sub = pool.subscribe(
      relays,
      {
        kinds: [NostrConnect],
        '#p': [clientPubkey],
        since: Math.floor(Date.now() / 1000) - 60,
      },
      {
        maxWait: NIP46_REQUEST_TIMEOUT_MS,
        abort: input.abortSignal,
        onevent(event) {
          const signerPubkey = /^[0-9a-f]{64}$/i.test(event.pubkey) ? event.pubkey.toLowerCase() : undefined;
          if (signerPubkey) {
            emitNostrConnectStatus(input.onStatus, relays, {
              type: 'signer-seen',
              clientPubkey,
              signerPubkey,
            });
          }
          try {
            const response = JSON.parse(
              nip44Decrypt(event.content, getConversationKey(input.clientSecretKey, event.pubkey)),
            ) as Nip46Response;
            if (response.result === secret && /^[0-9a-f]{64}$/i.test(event.pubkey)) {
              emitNostrConnectStatus(input.onStatus, relays, {
                type: 'response-received',
                phase: 'pairing',
                clientPubkey,
                signerPubkey: event.pubkey.toLowerCase(),
              });
              finish(null, event.pubkey);
            }
          } catch {
            // Ignore unrelated/malformed events addressed to the temporary client pubkey.
          }
        },
        onclose(reasons) {
          if (settled) return;
          emitNostrConnectStatus(input.onStatus, relays, {
            type: 'error',
            phase: 'subscription',
            clientPubkey,
            message: Array.isArray(reasons) ? reasons.join(',') : 'nostrconnect-subscription-closed',
          });
          finish(new Error('nostrconnect-subscription-closed'));
        },
      },
    );
  });
}

class RobustBunkerClient implements Nip46SignerClient {
  private readonly pool: SimplePool;
  private readonly conversationKey: Uint8Array;
  private readonly clientPubkey: string;
  private relays: string[];
  private sub?: SubCloser;
  private serial = 0;
  private closed = false;
  private cachedPubkey?: string;
  private readonly idPrefix = Math.random().toString(36).slice(2);
  private readonly listeners = new Map<string, {
    resolve: (result: string) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
    method: string;
  }>();

  constructor(
    private readonly clientSecretKey: Uint8Array,
    private readonly pointer: BunkerPointer,
    private readonly onStatus?: NostrConnectStatusHandler,
  ) {
    this.clientPubkey = getPublicKey(clientSecretKey);
    this.conversationKey = getConversationKey(clientSecretKey, pointer.pubkey);
    this.relays = [...pointer.relays];
    this.pool = createInstrumentedNostrConnectPool({
      relays: this.relays,
      onStatus,
      clientPubkey: this.clientPubkey,
      signerPubkey: pointer.pubkey,
    });
  }

  private emit(status: Omit<NostrConnectStatus, 'timestamp' | 'relays'>): void {
    emitNostrConnectStatus(this.onStatus, this.relays, {
      clientPubkey: this.clientPubkey,
      signerPubkey: this.pointer.pubkey,
      ...status,
    });
  }

  private setupSubscription(): void {
    if (this.sub || this.closed) return;
    this.emit({ type: 'relay-connecting', phase: 'request' });
    const sub = this.pool.subscribe(
      this.relays,
      {
        kinds: [NostrConnect],
        authors: [this.pointer.pubkey],
        '#p': [this.clientPubkey],
        since: Math.floor(Date.now() / 1000) - 60,
      },
      {
        maxWait: NIP46_REQUEST_TIMEOUT_MS,
        onevent: event => this.handleResponseEvent(event),
        onclose: () => {
          if (this.sub === sub) this.sub = undefined;
        },
      },
    );
    this.sub = sub;
  }

  private handleResponseEvent(event: NostrEvent): void {
    try {
      const response = JSON.parse(nip44Decrypt(event.content, this.conversationKey)) as Nip46Response;
      if (!response.id) return;
      const listener = this.listeners.get(response.id);
      if (!listener) return;
      clearTimeout(listener.timer);
      this.listeners.delete(response.id);
      this.emit({
        type: 'response-received',
        phase: 'response',
        method: listener.method,
        requestId: response.id,
      });
      if (response.error) {
        const err = new Error(response.error);
        this.emit({
          type: 'error',
          phase: 'response',
          method: listener.method,
          requestId: response.id,
          message: err.message,
          error: err,
        });
        listener.reject(err);
      } else {
        listener.resolve(response.result ?? '');
      }
    } catch {
      // Ignore unrelated/malformed events.
    }
  }

  private async sendRequest(method: string, params: string[]): Promise<string> {
    if (this.closed) throw new Error('this signer is not open anymore, create a new one');
    this.setupSubscription();
    const id = `${this.idPrefix}-${++this.serial}`;
    const content = nip44Encrypt(
      JSON.stringify({ id, method, params }),
      this.conversationKey,
    );
    const event = finalizeEvent({
      kind: NostrConnect,
      tags: [['p', this.pointer.pubkey]],
      content,
      created_at: Math.floor(Date.now() / 1000),
    }, this.clientSecretKey) as NostrEvent;

    const response = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.listeners.delete(id);
        const err = new Error(`nip46-${method}-timeout`);
        this.emit({
          type: 'timeout',
          phase: 'request',
          method,
          requestId: id,
          timeoutMs: NIP46_REQUEST_TIMEOUT_MS,
          message: err.message,
          error: err,
        });
        reject(err);
      }, NIP46_REQUEST_TIMEOUT_MS);
      this.listeners.set(id, { resolve, reject, timer, method });
    });
    this.emit({
      type: 'request-sent',
      phase: 'request',
      method,
      requestId: id,
    });

    void firstFulfilled(this.pool.publish(this.relays, event, { maxWait: NIP46_REQUEST_TIMEOUT_MS }))
      .catch(() => {
        const listener = this.listeners.get(id);
        if (!listener) return;
        clearTimeout(listener.timer);
        this.listeners.delete(id);
        const err = new Error(`nip46-${method}-publish-failed`);
        this.emit({
          type: 'error',
          phase: 'publish',
          method,
          requestId: id,
          message: err.message,
          error: err,
        });
        listener.reject(err);
      });

    return response;
  }

  async connect(): Promise<void> {
    await this.sendRequest('connect', [this.pointer.pubkey, this.pointer.secret ?? '']);
  }

  async getPublicKey(): Promise<string> {
    if (!this.cachedPubkey) {
      const pubkey = (await this.sendRequest('get_public_key', [])).trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('invalid-pubkey-from-bunker');
      this.cachedPubkey = pubkey;
    }
    return this.cachedPubkey;
  }

  async signEvent(event: EventTemplate): Promise<NostrEvent> {
    const signed = JSON.parse(await this.sendRequest('sign_event', [JSON.stringify(event)])) as NostrEvent;
    if (!verifyEvent(signed)) throw new Error(`event returned from bunker is improperly signed: ${JSON.stringify(signed)}`);
    return signed;
  }

  async nip04Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return this.sendRequest('nip04_encrypt', [peerPubkey, plaintext]);
  }

  async nip04Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return this.sendRequest('nip04_decrypt', [peerPubkey, ciphertext]);
  }

  async nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return this.sendRequest('nip44_encrypt', [peerPubkey, plaintext]);
  }

  async nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return this.sendRequest('nip44_decrypt', [peerPubkey, ciphertext]);
  }

  async ping(): Promise<void> {
    const response = await this.sendRequest('ping', []);
    if (response !== 'pong') throw new Error(`result is not pong: ${response}`);
  }

  async switchRelays(): Promise<boolean> {
    try {
      const response = await this.sendRequest('switch_relays', []);
      const parsed = JSON.parse(response) as unknown;
      if (parsed === null) return false;
      if (!Array.isArray(parsed)) return false;
      const nextRelays = Array.from(new Set(parsed
        .map(relay => typeof relay === 'string' ? relay.trim() : '')
        .filter(relay => /^wss?:\/\//.test(relay))));
      if (nextRelays.length !== parsed.length || nextRelays.length === 0) return false;
      const same = JSON.stringify([...nextRelays].sort()) === JSON.stringify([...this.relays].sort());
      if (same) return false;
      const previousSub = this.sub;
      this.relays = nextRelays;
      setTimeout(() => previousSub?.close('switch-relays'), 5_000);
      this.sub = undefined;
      this.setupSubscription();
      return true;
    } catch {
      return false;
    }
  }

  async logout(): Promise<void> {
    const response = await this.sendRequest('logout', []);
    if (response !== 'ack') throw new Error(`result is not ack: ${response}`);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.sub?.close('closed by caller');
    this.sub = undefined;
    for (const [id, listener] of this.listeners) {
      clearTimeout(listener.timer);
      listener.reject(new Error('bunker-closed'));
      this.listeners.delete(id);
    }
    this.pool.destroy();
  }
}

/**
 * App-initiated NIP-46: we generate a `nostrconnect://` URI containing our
 * client pubkey, relay, secret, and requested perms. The user pastes/scans
 * it into their signer, which then connects to the relay and acks. Returns
 * a BunkerSignerImpl once the handshake completes (or rejects on abort).
 *
 *   uri              — the nostrconnect:// URI shown to the user (built by
 *                      the caller via buildNostrConnectUri)
 *   clientSecretKey  — the 32-byte session key the URI was built with
 *   abortSignal      — cancel a long-running wait when the modal closes
 *   timeoutMs        — pairing wait deadline; defaults to 5 minutes
 *   onStatus         — detailed pairing and NIP-46 request progress events
 */
export async function createBunkerSignerFromNostrConnect(input: {
  uri: string;
  clientSecretKey: Uint8Array;
  abortSignal?: AbortSignal;
  timeoutMs?: number;
  onStatus?: NostrConnectStatusHandler;
}): Promise<BunkerSignerImpl> {
  const { uri, clientSecretKey, abortSignal, timeoutMs, onStatus } = input;
  if (clientSecretKey.length !== 32) throw new Error('invalid-client-secret-key');

  const { signerPubkey, relays, secret } = await waitForNostrConnectApproval({
    uri,
    clientSecretKey,
    abortSignal,
    timeoutMs,
    onStatus,
  });
  if (!/^[0-9a-f]{64}$/i.test(signerPubkey)) throw new Error('invalid-pubkey-from-bunker');

  const normalizedBunkerUri = buildBunkerUriFromNostrConnectUri(uri, signerPubkey);
  const bunker = new RobustBunkerClient(clientSecretKey, {
    pubkey: signerPubkey,
    relays,
    secret,
  }, onStatus);
  let pubkey: string;
  try {
    pubkey = await bunker.getPublicKey();
    await bestEffortSwitchRelays(bunker);
  } catch (err) {
    await bunker.close().catch(() => {});
    throw err;
  }
  return new BunkerSignerImpl(pubkey.toLowerCase(), bunker, normalizedBunkerUri, clientSecretKey);
}

/**
 * Build a NIP-46 `nostrconnect://` URI for the app-initiated flow. The
 * `secret` is echoed back by the bunker on connect so the app can verify
 * it's talking to the right peer; it must be unguessable.
 */
export function buildNostrConnectUri(input: {
  clientPubkeyHex: string;
  relayUrl?: string;
  relayUrls?: string[];
  secret: string;
  perms?: string[];
  appName?: string;
  appUrl?: string;
}): string {
  const { clientPubkeyHex, secret } = input;
  if (!/^[0-9a-f]{64}$/i.test(clientPubkeyHex)) throw new Error('invalid-client-pubkey');

  const relayUrls = input.relayUrls ?? (input.relayUrl ? [input.relayUrl] : []);
  const cleanRelayUrls = relayUrls.map(relay => relay.trim()).filter(Boolean);
  if (cleanRelayUrls.length === 0) throw new Error('relay-url-required');
  for (const relayUrl of cleanRelayUrls) {
    if (!/^wss?:\/\//.test(relayUrl)) throw new Error('invalid-relay-url');
  }

  const params = new URLSearchParams();
  for (const relayUrl of cleanRelayUrls) params.append('relay', relayUrl);
  params.set('secret', secret);
  if (input.perms && input.perms.length > 0) params.set('perms', input.perms.join(','));
  if (input.appName) params.set('name', input.appName);
  if (input.appUrl) params.set('url', input.appUrl);
  return `nostrconnect://${clientPubkeyHex}?${params.toString()}`;
}

/**
 * Convert an app-generated `nostrconnect://` pairing URI into the equivalent
 * signer-published `bunker://` reconnect URI once the signer pubkey is known.
 *
 * `nostrconnect://` is a one-time app-to-signer invitation; it only contains
 * the client pubkey. After the signer responds, future restores should use
 * `bunker://signerPubkey?...` with the same relays and secret.
 */
export function buildBunkerUriFromNostrConnectUri(nostrConnectUri: string, signerPubkeyHex: string): string {
  if (!/^[0-9a-f]{64}$/i.test(signerPubkeyHex)) throw new Error('invalid-signer-pubkey');
  let parsed: URL;
  try {
    parsed = new URL(nostrConnectUri);
  } catch {
    throw new Error('invalid-nostrconnect-uri');
  }
  if (parsed.protocol !== 'nostrconnect:') throw new Error('invalid-nostrconnect-uri');

  const relays = parsed.searchParams.getAll('relay').map(relay => relay.trim()).filter(Boolean);
  if (relays.length === 0) throw new Error('relay-url-required');
  for (const relayUrl of relays) {
    if (!/^wss?:\/\//.test(relayUrl)) throw new Error('invalid-relay-url');
  }

  const secret = parsed.searchParams.get('secret');
  const params = new URLSearchParams();
  for (const relayUrl of relays) params.append('relay', relayUrl);
  if (secret) params.set('secret', secret);
  return `bunker://${signerPubkeyHex.toLowerCase()}?${params.toString()}`;
}

export function isBunkerUri(value: string): boolean {
  return value.trim().toLowerCase().startsWith('bunker://');
}

export function isNostrConnectUri(value: string): boolean {
  return value.trim().toLowerCase().startsWith('nostrconnect://');
}

export function isSupportedPairingUri(value: string): boolean {
  return isBunkerUri(value) || isNostrConnectUri(value);
}

/**
 * Race a bunker handshake against a deadline. nostr-tools' `BunkerSigner`
 * `sendRequest` has no per-request timeout — it publishes the request and only
 * settles when a matching response arrives on the subscription. If the remote
 * signer never replies (relay unreachable, or the bunker server is already gone
 * — e.g. signet-app's in-page NIP-46 server after a same-tab redirect navigated
 * it away), `connect()`/`getPublicKey()` hang forever. On timeout we close the
 * half-open signer (releasing its relay subscription) and reject so the caller
 * can fall back. `Promise.race` keeps a rejection handler attached to `p`, so a
 * late rejection from the abandoned handshake won't surface as unhandled.
 */
async function raceBunkerHandshake<T>(
  p: Promise<T>,
  ms: number,
  bunker: { close: () => Promise<void> },
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      void bunker.close().catch(() => {});
      reject(new Error('bunker-connect-timeout'));
    }, ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function bestEffortSwitchRelays(
  bunker: { switchRelays: () => Promise<boolean> },
  timeoutMs = 1_000,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      bunker.switchRelays(),
      new Promise(resolve => {
        timer = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } catch {
    // Relay migration is advisory; keep the session usable on the current relays.
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Connect a bunker session from a `bunker://` URI or NIP-05 identifier. Pass
 * `clientSecretKey` to bind a stable client pubkey the signer can auto-approve
 * (see `loadOrCreatePersistentClientSk`); when omitted a fresh ephemeral key is
 * generated, which a per-pubkey-approving bunker will treat as a new,
 * unapproved client.
 */
export async function createBunkerSigner(input: {
  uri: string;
  clientSecretKey?: Uint8Array;
  onauth?: (url: string) => void;
  onStatus?: NostrConnectStatusHandler;
  /**
   * Bound the NIP-46 `connect` + `get_public_key` handshake, in milliseconds.
   * Omit for the interactive paste flow, where a cold remote signer may
   * legitimately take tens of seconds to approve via the `auth_url` callback.
   * Set it for unattended boot-time connects (redirect-bunker auto-pair,
   * session restore) where a non-responding signer must degrade to the
   * auth-only fallback rather than stall. On expiry the half-open signer is
   * closed and the call rejects with `bunker-connect-timeout`.
   */
  timeoutMs?: number;
}): Promise<BunkerSignerImpl> {
  const trimmed = input.uri.trim();
  if (!trimmed) throw new Error('empty-bunker-uri');

  const pointer: BunkerPointer | null = await parseBunkerInput(trimmed);
  if (!pointer) throw new Error('invalid-bunker-uri');

  const sk = input.clientSecretKey ?? generateSecretKey();
  if (sk.length !== 32) throw new Error('invalid-client-secret-key');

  const bunker = new RobustBunkerClient(sk, pointer, input.onStatus);
  const handshake = (async (): Promise<string> => {
    await bunker.connect();
    return bunker.getPublicKey();
  })();
  let pubkey: string;
  try {
    pubkey = input.timeoutMs && input.timeoutMs > 0
      ? await raceBunkerHandshake(handshake, input.timeoutMs, bunker)
      : await handshake;
  } catch (err) {
    await bunker.close().catch(() => {});
    throw err;
  }
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
    await bunker.close().catch(() => {});
    throw new Error('invalid-pubkey-from-bunker');
  }
  await bestEffortSwitchRelays(bunker);

  return new BunkerSignerImpl(pubkey.toLowerCase(), bunker, trimmed, sk);
}

/** Generate a 32-byte secret key. */
export function generateSecretKey(): Uint8Array {
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  return sk;
}

// ── nsec (local privkey, in-memory only) ─────────────────────────────────────

/**
 * Holds a 32-byte private key in memory, signs locally with schnorr, exposes
 * NIP-44 via nostr-tools. The key is never persisted by this signer — the SDK
 * will not call any storage write for an nsec session, so reloads land back
 * on the picker. The consumer must surface the security trade-off in the UI.
 */
export class LocalSigner implements SignetSigner {
  readonly method = 'nsec' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: true, hasNip44: true };
  readonly nip04: SignetSigner['nip04'];
  readonly nip44: SignetSigner['nip44'];

  constructor(public readonly pubkey: string, private readonly privkey: Uint8Array) {
    this.nip04 = {
      encrypt: async (peer, pt) => nip04Encrypt(this.privkey, peer, pt),
      decrypt: async (peer, ct) => nip04Decrypt(this.privkey, peer, ct),
    };
    this.nip44 = {
      encrypt: async (peer, pt) => nip44Encrypt(pt, getConversationKey(this.privkey, peer)),
      decrypt: async (peer, ct) => nip44Decrypt(ct, getConversationKey(this.privkey, peer)),
    };
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    const filled = {
      kind: template.kind,
      content: template.content,
      created_at: template.created_at ?? Math.floor(Date.now() / 1000),
      tags: template.tags ?? [],
    };
    return finalizeEvent(filled, this.privkey) as NostrEvent;
  }

  async close(): Promise<void> {
    // Best-effort wipe — the engine may already have copies in CoW pages, but
    // zeroing here at least gives a consistent shape with bunker.close().
    this.privkey.fill(0);
  }
}

/**
 * Decode a bech32 nsec into a LocalSigner. Accepts either the `nsec1...`
 * prefix or a raw 64-char hex private key for power-user paste paths.
 * Throws on any malformed input — caller surfaces the error to the user.
 */
export function createLocalSignerFromNsec(input: string): LocalSigner {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('empty-nsec');

  let sk: Uint8Array;
  if (trimmed.startsWith('nsec1')) {
    const decoded = nip19Decode(trimmed);
    if (decoded.type !== 'nsec') throw new Error('not-an-nsec');
    sk = decoded.data as Uint8Array;
  } else if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    sk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) sk[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  } else {
    throw new Error('invalid-nsec-format');
  }
  if (sk.length !== 32) throw new Error('invalid-nsec-length');

  const pubkey = getPublicKey(sk);
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('invalid-pubkey-from-nsec');
  return new LocalSigner(pubkey.toLowerCase(), sk);
}

// ── Ephemeral (redirect-only) ─────────────────────────────────────────────────

/**
 * Auth-only signer returned by the redirect/QR flow before Option B is built.
 * Holds the signed challenge but cannot sign further events.
 */
export class EphemeralSigner implements SignetSigner {
  readonly method = 'redirect' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: false, hasNip44: false };

  constructor(public readonly pubkey: string, public readonly authEvent: SignetAuthEvent) {}

  async signEvent(_template: EventTemplate): Promise<NostrEvent> {
    throw new Error(
      'signer-auth-only: this session was established via redirect and cannot sign new events. ' +
      'Install a NIP-07 extension (bark, Alby) or paste a bunker URI to upgrade.',
    );
  }

  async close(): Promise<void> {
    // nothing to close
  }
}

/**
 * A redirect-bunker signer whose bunker connects in the BACKGROUND.
 *
 * `handleRedirectCallback` returns this immediately so the consumer can paint a
 * signed-in UI without waiting on an up-to-8s bunker handshake over flaky
 * relays (the cause of the "blank screen on sign-in"). The authenticated pubkey
 * is known up front; the first `signEvent` / `nip44` call awaits the background
 * connect. If that connect fails, signing rejects with the auth-only error —
 * the session is still valid for identity proof.
 */
export class DeferredBunkerSigner implements SignetSigner {
  readonly method = 'bunker' as const;
  readonly capabilities: SignerCapabilities;
  readonly nip04: SignetSigner['nip04'];
  readonly nip44: SignetSigner['nip44'];
  readonly nip46: SignetSigner['nip46'];

  constructor(
    public readonly pubkey: string,
    public readonly authEvent: SignetAuthEvent,
    /** Resolves to the connected bunker, or null if the connect failed. */
    private readonly upgrade: Promise<BunkerSignerImpl | null>,
    /** Original bunker URI — exposed so persistence can reconnect on reload. */
    public readonly bunkerUri?: string,
    /** Stable client key — exposed so persistence keeps the same NIP-46 client pubkey. */
    public readonly clientSecretKey?: Uint8Array,
    optimisticCapabilities = true,
  ) {
    this.capabilities = {
      canSignEvents: optimisticCapabilities,
      hasNip44: optimisticCapabilities,
    };
    void this.upgrade.then(signer => {
      if (signer) {
        this.capabilities.canSignEvents = true;
        this.capabilities.hasNip44 = true;
      }
    });
    this.nip04 = {
      encrypt: async (peer, pt) => (await this.live()).nip04!.encrypt(peer, pt),
      decrypt: async (peer, ct) => (await this.live()).nip04!.decrypt(peer, ct),
    };
    this.nip44 = {
      encrypt: async (peer, pt) => (await this.live()).nip44!.encrypt(peer, pt),
      decrypt: async (peer, ct) => (await this.live()).nip44!.decrypt(peer, ct),
    };
    this.nip46 = {
      ping: async () => (await this.live()).nip46!.ping(),
      switchRelays: async () => (await this.live()).nip46!.switchRelays(),
      logout: async () => (await this.live()).nip46!.logout(),
    };
  }

  private async live(): Promise<BunkerSignerImpl> {
    const signer = await this.upgrade;
    if (!signer) {
      throw new Error(
        'signer-auth-only: the redirect bunker handoff did not connect, so this ' +
        'session cannot sign. Reconnect the signer or paste a bunker URI to upgrade.',
      );
    }
    return signer;
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    return (await this.live()).signEvent(template);
  }

  async close(): Promise<void> {
    const signer = await this.upgrade.catch(() => null);
    if (signer) await signer.close().catch(() => { /* ignore */ });
  }
}
