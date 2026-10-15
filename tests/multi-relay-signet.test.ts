/**
 * The redirect / QR Signet flow (`remote-signet`, `local-signet`) carries and
 * listens on up to three relays. Wire contract: the `?auth=1` URL repeats
 * `relay=` once per relay, PRIMARY FIRST, at most 3 — old My Signet builds read
 * only the first, so primary-first keeps them working unchanged.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('signet-verify', async importOriginal => ({
  ...(await importOriginal<typeof import('signet-verify')>()),
  waitForAuthResponse: vi.fn(() => new Promise(() => { /* overridden per test */ })),
}));

import { bytesToHex } from '@noble/hashes/utils';
import { waitForAuthResponse } from 'signet-verify';
import { login } from '../src/signet-login.js';
import { buildAuthRelayList, waitForAuthResponseOnRelays } from '../src/relay-wait.js';
import { loadPendingRelayAuth, savePendingRelayAuth } from '../src/storage.js';
import type { PendingRelayAuth, SignetStorage } from '../src/types.js';
import { makeAuthEvent } from './helpers/auth-event.js';

const CHALLENGE = 'b'.repeat(64);
const NOS = 'wss://nos.lol';
const PRIMAL = 'wss://relay.primal.net';
const MOM = 'wss://nostr.mom';

function installDialogPolyfill(): void {
  if (typeof HTMLDialogElement.prototype.showModal !== 'function') {
    HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
  }
  if (typeof HTMLDialogElement.prototype.close !== 'function') {
    HTMLDialogElement.prototype.close = function close() { this.removeAttribute('open'); };
  }
}

async function settleMicrotasks(rounds = 8): Promise<void> {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}

function authUrl(): URL {
  const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement;
  return new URL(link.href);
}

function codedError(code: string): Error & { code: string } {
  const err = new Error(code) as Error & { code: string };
  err.code = code;
  return err;
}

/** A fake wait: settles per relay via `script`, otherwise pends until aborted. */
interface Wait { relayUrl: string; signal: AbortSignal; resolve(v: unknown): void; reject(e: unknown): void }
function installWaits(): Wait[] {
  const waits: Wait[] = [];
  vi.mocked(waitForAuthResponse).mockReset();
  vi.mocked(waitForAuthResponse).mockImplementation(((o: { relayUrl: string; abortSignal: AbortSignal }) =>
    new Promise((resolve, reject) => {
      const w: Wait = { relayUrl: o.relayUrl, signal: o.abortSignal, resolve, reject };
      waits.push(w);
      o.abortSignal.addEventListener('abort', () => reject(codedError('aborted')), { once: true });
    })) as never);
  return waits;
}

describe('buildAuthRelayList', () => {
  it('puts the primary first, then the rest in order', () => {
    expect(buildAuthRelayList(PRIMAL, [NOS, PRIMAL, MOM])).toEqual([PRIMAL, NOS, MOM]);
  });

  it('dedupes ignoring case and one trailing slash, keeping the first spelling', () => {
    expect(buildAuthRelayList(NOS, ['WSS://NOS.LOL/', PRIMAL, 'wss://relay.primal.net/'])).toEqual([NOS, PRIMAL]);
  });

  it('caps at three', () => {
    expect(buildAuthRelayList(NOS, [PRIMAL, MOM, 'wss://a.example', 'wss://b.example'])).toEqual([NOS, PRIMAL, MOM]);
  });

  it('is just the primary when there is nothing else', () => {
    expect(buildAuthRelayList(NOS)).toEqual([NOS]);
    expect(buildAuthRelayList(NOS, [NOS])).toEqual([NOS]);
  });
});

describe('auth URL carries every relay', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    vi.mocked(waitForAuthResponse).mockImplementation(() => new Promise(() => { /* pends */ }));
  });
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ''; });

  // Returned in a box: an async function returning the login promise would
  // flatten it and wait for the whole sign-in.
  async function start(extra: Record<string, unknown>): Promise<{ pending: Promise<unknown> }> {
    const pending = login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet', persist: false, ...extra,
    });
    await settleMicrotasks();
    return { pending };
  }
  async function cancel(pending: Promise<unknown>): Promise<void> {
    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  }

  it('repeats relay= once per relay, primary first (KithMoot shape)', async () => {
    const { pending } = await start({ relayUrls: [NOS, PRIMAL, MOM] });
    const url = authUrl();
    expect(url.searchParams.getAll('relay')).toEqual([NOS, PRIMAL, MOM]);
    expect(url.searchParams.get('relay')).toBe(NOS); // what an old build reads
    expect(url.searchParams.get('sessionPubkey')).toMatch(/^[0-9a-f]{64}$/);
    await cancel(pending);
  });

  it('puts an explicit relayUrl first and dedupes it out of relayUrls', async () => {
    const { pending } = await start({ relayUrl: MOM, relayUrls: [NOS, PRIMAL, MOM] });
    expect(authUrl().searchParams.getAll('relay')).toEqual([MOM, NOS, PRIMAL]);
    await cancel(pending);
  });

  it('caps the link at three relays', async () => {
    const { pending } = await start({ relayUrls: [NOS, PRIMAL, MOM, 'wss://a.example', 'wss://b.example'] });
    expect(authUrl().searchParams.getAll('relay')).toEqual([NOS, PRIMAL, MOM]);
    await cancel(pending);
  });

  it('leaves a single relay exactly as before', async () => {
    const { pending } = await start({ relayUrl: 'wss://relay.example.com' });
    expect(authUrl().searchParams.getAll('relay')).toEqual(['wss://relay.example.com']);
    expect(waitForAuthResponse).toHaveBeenCalledTimes(1);
    await cancel(pending);
  });

  it('listens on every relay in the link', async () => {
    const { pending } = await start({ relayUrls: [NOS, PRIMAL, MOM] });
    const relays = vi.mocked(waitForAuthResponse).mock.calls.map(c => (c[0] as { relayUrl: string }).relayUrl);
    expect(relays).toEqual([NOS, PRIMAL, MOM]);
    await cancel(pending);
  });

  it('stores relayUrls on the pending record, keeping relayUrl as the primary', async () => {
    const { pending } = await start({ relayUrls: [NOS, PRIMAL, MOM] });
    const record = await loadPendingRelayAuth();
    expect(record?.relayUrl).toBe(NOS);
    expect(record?.relayUrls).toEqual([NOS, PRIMAL, MOM]);
    await cancel(pending);
  });
});

describe('listening across relays', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
  });
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ''; });

  it('signs in from a response that arrives only on relay #2, then closes every subscription', async () => {
    const waits = installWaits();
    const pending = login({
      appName: 'KithMoot', challenge: CHALLENGE, theme: 'dark', preferredMethod: 'remote-signet',
      relayUrls: [NOS, PRIMAL, MOM], persist: false,
    });
    await settleMicrotasks();
    expect(waits.map(w => w.relayUrl)).toEqual([NOS, PRIMAL, MOM]);
    expect(waits.every(w => !w.signal.aborted)).toBe(true);

    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: window.location.origin });
    waits[1].resolve({ pubkey: authEvent.pubkey, authEvent });

    const session = await pending as { pubkey: string; method: string };
    expect(session.pubkey).toBe(authEvent.pubkey);
    expect(session.method).toBe('redirect');
    expect(waits.every(w => w.signal.aborted)).toBe(true);
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it('closes every subscription on cancel', async () => {
    const waits = installWaits();
    const pending = login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet',
      relayUrls: [NOS, PRIMAL, MOM], persist: false,
    });
    await settleMicrotasks();
    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
    expect(waits).toHaveLength(3);
    expect(waits.every(w => w.signal.aborted)).toBe(true);
  });
});

describe('waitForAuthResponseOnRelays', () => {
  const base = { requestId: CHALLENGE, sessionPrivKey: new Uint8Array(32).fill(1), expectedOrigin: 'https://app.example' };
  beforeEach(() => { vi.mocked(waitForAuthResponse).mockReset(); });

  it('with one relay is a straight pass-through, keeping the caller signal', () => {
    const waits = installWaits();
    const ctl = new AbortController();
    void waitForAuthResponseOnRelays({ ...base, abortSignal: ctl.signal }, [NOS]).catch(() => {});
    expect(waits).toHaveLength(1);
    expect(waits[0].signal).toBe(ctl.signal);
  });

  it('first valid response wins; a duplicate on another relay is ignored', async () => {
    const waits = installWaits();
    const p = waitForAuthResponseOnRelays(base, [NOS, PRIMAL, MOM]);
    waits[2].resolve({ pubkey: 'p3' });
    waits[1].resolve({ pubkey: 'p2' }); // same event, later
    await expect(p).resolves.toEqual({ pubkey: 'p3' });
    expect(waits.every(w => w.signal.aborted)).toBe(true);
  });

  it('survives failing relays while another can still deliver', async () => {
    const waits = installWaits();
    const p = waitForAuthResponseOnRelays(base, [NOS, PRIMAL, MOM]);
    waits[0].reject(codedError('relay-error'));
    waits[1].reject(codedError('relay-refused'));
    await settleMicrotasks();
    expect(waits[2].signal.aborted).toBe(false);
    waits[2].resolve({ pubkey: 'ok' });
    await expect(p).resolves.toEqual({ pubkey: 'ok' });
  });

  it('rejects once every relay has failed, with the most informative error', async () => {
    const waits = installWaits();
    const p = waitForAuthResponseOnRelays(base, [NOS, PRIMAL, MOM]);
    waits[0].reject(codedError('relay-error'));
    waits[1].reject(codedError('timeout'));
    waits[2].reject(codedError('relay-closed'));
    await expect(p).rejects.toMatchObject({ code: 'timeout' });
  });

  it('treats a denial on any relay as final and closes the rest', async () => {
    const waits = installWaits();
    const p = waitForAuthResponseOnRelays(base, [NOS, PRIMAL, MOM]);
    waits[1].reject(codedError('denied'));
    await expect(p).rejects.toMatchObject({ code: 'denied' });
    expect(waits.every(w => w.signal.aborted)).toBe(true);
  });

  it('aborts every subscription when the caller aborts, rejecting aborted', async () => {
    const waits = installWaits();
    const ctl = new AbortController();
    const p = waitForAuthResponseOnRelays({ ...base, abortSignal: ctl.signal }, [NOS, PRIMAL, MOM]);
    ctl.abort();
    await expect(p).rejects.toMatchObject({ code: 'aborted' });
    expect(waits.every(w => w.signal.aborted)).toBe(true);
  });

  it('settles only after every underlying wait has joined', async () => {
    const waits = installWaits();
    // Relay 3 is slow to unwind after being aborted.
    vi.mocked(waitForAuthResponse).mockImplementation(((o: { relayUrl: string; abortSignal: AbortSignal }) =>
      new Promise((resolve, reject) => {
        const w: Wait = { relayUrl: o.relayUrl, signal: o.abortSignal, resolve, reject };
        waits.push(w);
        if (o.relayUrl !== MOM) o.abortSignal.addEventListener('abort', () => reject(codedError('aborted')), { once: true });
      })) as never);
    waits.length = 0;
    const p = waitForAuthResponseOnRelays(base, [NOS, PRIMAL, MOM]);
    let done = false;
    void p.then(() => { done = true; });
    waits[0].resolve({ pubkey: 'ok' });
    await settleMicrotasks();
    expect(done).toBe(false);
    waits[2].reject(codedError('aborted'));
    await expect(p).resolves.toEqual({ pubkey: 'ok' });
  });
});

function requiredStorage(): SignetStorage {
  const data = new Map<string, string>();
  return {
    required: true,
    async compareAndSetItem(key, expected, value) {
      if ((data.get(key) ?? null) !== expected) return false;
      if (value === null) data.delete(key); else data.set(key, value);
      return true;
    },
    async getItems(keys) { return Object.fromEntries(keys.map(key => [key, data.get(key) ?? null])); },
    async setItems(changes, expected) {
      if (Object.entries(expected).some(([key, value]) => (data.get(key) ?? null) !== value)) return false;
      for (const [key, value] of Object.entries(changes)) { if (value === null) data.delete(key); else data.set(key, value); }
      return true;
    },
    async getItem(key) { return data.get(key) ?? null; },
    async setItem(key, value) { data.set(key, value); },
    async removeItem(key) { data.delete(key); },
  };
}

describe('resuming a pending record', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    vi.mocked(waitForAuthResponse).mockImplementation(() => new Promise(() => { /* pends */ }));
  });
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ''; });

  function record(overrides: Partial<PendingRelayAuth> = {}): PendingRelayAuth {
    return {
      challenge: 'd'.repeat(64),
      origin: window.location.origin,
      appName: 'KithMoot',
      relayUrl: NOS,
      sessionSkHex: 'e'.repeat(64),
      issuedAt: Math.floor(Date.now() / 1000) - 30,
      ...overrides,
    };
  }

  async function cancel(pending: Promise<unknown>): Promise<void> {
    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  }

  it('resumes an old record without relayUrls as a single-relay request', async () => {
    const old = record();
    expect('relayUrls' in old).toBe(false);
    await savePendingRelayAuth(old);

    const pending = login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet',
      relayUrls: [NOS, PRIMAL, MOM], persist: false,
    });
    await settleMicrotasks();

    expect(authUrl().searchParams.getAll('relay')).toEqual([NOS]);
    expect(authUrl().searchParams.get('challenge')).toBe(old.challenge);
    const calls = vi.mocked(waitForAuthResponse).mock.calls.map(c => c[0] as { relayUrl: string; sessionPrivKey: Uint8Array });
    expect(calls.map(c => c.relayUrl)).toEqual([NOS]);
    expect(bytesToHex(calls[0].sessionPrivKey)).toBe(old.sessionSkHex);
    await cancel(pending);
  });

  it('rebuilds the identical link (same relays, same order) from a multi-relay record', async () => {
    await savePendingRelayAuth(record({ relayUrl: PRIMAL, relayUrls: [PRIMAL, MOM, NOS] }));

    const pending = login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet',
      relayUrls: [NOS, PRIMAL, MOM], persist: false,
    });
    await settleMicrotasks();

    expect(authUrl().searchParams.getAll('relay')).toEqual([PRIMAL, MOM, NOS]);
    const relays = vi.mocked(waitForAuthResponse).mock.calls.map(c => (c[0] as { relayUrl: string }).relayUrl);
    expect(relays).toEqual([PRIMAL, MOM, NOS]);
    await cancel(pending);
  });

  it('compares only the primary relay for the required-storage binding', async () => {
    const storage = requiredStorage();
    await savePendingRelayAuth(record({ relayUrl: NOS, relayUrls: [NOS, MOM] }), storage);

    // Same primary, different secondary set: resumes (no binding mismatch).
    const pending = login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet',
      relayUrl: NOS, relayUrls: [NOS, PRIMAL], storage,
    });
    await settleMicrotasks();
    expect(authUrl().searchParams.getAll('relay')).toEqual([NOS, MOM]);
    await cancel(pending);
  });

  it('still refuses a required-storage resume whose primary relay differs', async () => {
    const storage = requiredStorage();
    await savePendingRelayAuth(record({ relayUrl: NOS, relayUrls: [NOS, MOM] }), storage);
    await expect(login({
      appName: 'KithMoot', theme: 'dark', preferredMethod: 'remote-signet',
      relayUrl: PRIMAL, relayUrls: [PRIMAL, NOS, MOM], storage,
    })).rejects.toThrow('required-storage-pending-relay-binding-mismatch');
  });

  it('rejects a record whose relayUrls is malformed', async () => {
    for (const bad of [[], 'wss://x', [1], ['wss://a', ''], [NOS, PRIMAL, MOM, 'wss://d.example']]) {
      localStorage.setItem('signet:login.pendingRelayAuth', JSON.stringify({ ...record(), relayUrls: bad }));
      expect(await loadPendingRelayAuth()).toBeNull();
    }
  });
});
