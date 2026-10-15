import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPinnedNip07SignerWithDiscoveryBoundary, HEADLESS_NIP07_PINNED_PROVIDER_CALLS } from '../src/signet-login.js';
import type { EventTemplate, Nip07DiscoveryBoundary, NostrEvent, SignerEffectBoundary } from '../src/types.js';

const key = 'a'.repeat(64);
const template: EventTemplate = { kind: 1, content: 'hello' };
const discovery: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1,
  start: (prepare, effect) => { prepare(); return effect(); } };
const setProvider = (provider: unknown) => { (window as unknown as { nostr: unknown }).nostr = provider; };
function fixture() {
  let active = false;
  const sign = vi.fn(function(this: unknown, event: EventTemplate) {
    expect(this).toBe(provider); expect(active).toBe(true);
    return Promise.resolve({ ...event, pubkey: key, id: 'b'.repeat(64), sig: 'c'.repeat(128) } as NostrEvent);
  });
  const family = () => {
    const crypto = {
      encrypt: vi.fn(function(this: unknown, peer: string, text: string) {
        expect(this).toBe(crypto); expect(active).toBe(true); return Promise.resolve(`${peer}:${text}`);
      }),
      decrypt: vi.fn(function(this: unknown, peer: string, text: string) {
        expect(this).toBe(crypto); expect(active).toBe(true); return Promise.resolve(`${text}:${peer}`);
      }),
    }; return crypto;
  };
  const provider = { getPublicKey: vi.fn(async () => key.toUpperCase()), signEvent: sign, nip04: family(), nip44: family() };
  const boundary: SignerEffectBoundary = { start: async effect => { active = true; try { return await effect(); } finally { active = false; } } };
  setProvider(provider); return { provider, sign, boundary };
}

afterEach(() => { delete window.nostr; vi.useRealTimers(); });

describe('captured NIP-07 provider callables', () => {
  it('normalises strict templates, preserves receivers, and freezes owned methods and metadata', async () => {
    const { boundary, sign } = fixture(); const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    expect(signer.pubkey).toBe(key); expect(signer.pinnedProviderCalls).toBe(1);
    for (const owned of [signer, signer.capabilities, signer.nip04, signer.nip44]) expect(Object.isFrozen(owned)).toBe(true);
    const signed = await signer.signEvent(template, boundary);
    expect(signed.created_at).toBeTypeOf('number'); expect(signed.tags).toEqual([]); expect(sign).toHaveBeenCalledOnce();
    for (const crypto of [signer.nip04!, signer.nip44!]) {
      expect(await crypto.encrypt('peer', 'text', boundary)).toBe('peer:text');
      expect(await crypto.decrypt('peer', 'text', boundary)).toBe('text:peer');
    }
    expect(() => Object.setPrototypeOf(signer, {})).toThrow();
    expect(() => Reflect.set(signer, 'signEvent', vi.fn())).not.toThrow();
    expect(Reflect.set(signer, 'signEvent', vi.fn())).toBe(false);
  });

  it('never reads provider or crypto properties after discovery, including a delayed boundary', async () => {
    const { provider, boundary, sign } = fixture();
    let sealed = false, reads = 0;
    const protect = <T extends object>(target: T): T => new Proxy(target, { get(object, property, receiver) {
      if (sealed) { reads++; throw new Error('late-provider-read'); } return Reflect.get(object, property, receiver);
    }});
    // Preserve receiver checks by wrapping only the outer provider and using a
    // callable that explicitly expects the captured Proxy receiver.
    const rawSign = vi.fn(function(this: unknown, event: EventTemplate) {
      expect(this).toBe(proxy); return Promise.resolve({ ...event, pubkey: key } as NostrEvent);
    });
    provider.signEvent = rawSign;
    for (const crypto of [provider.nip04, provider.nip44]) {
      crypto.encrypt = vi.fn(async (peer, text) => `${peer}:${text}`);
      crypto.decrypt = vi.fn(async (peer, text) => `${text}:${peer}`);
    }
    provider.nip04 = protect(provider.nip04); provider.nip44 = protect(provider.nip44);
    const proxy = protect(provider); setProvider(proxy);
    const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    sealed = true;
    Object.defineProperty(window, 'nostr', { configurable: true, get: () => { reads++; throw new Error('late-window-read'); } });
    let invoke!: () => void;
    const delayed: SignerEffectBoundary = { start: effect => new Promise((resolve, reject) => { invoke = () => { effect().then(resolve, reject); }; }) };
    const work = signer.signEvent(template, delayed); expect(rawSign).not.toHaveBeenCalled();
    invoke(); await work; expect(rawSign).toHaveBeenCalledOnce(); expect(sign).not.toHaveBeenCalled(); expect(reads).toBe(0);
    // Crypto receiver identity is the family captured during discovery, too.
    // These callbacks ignore `this`, avoiding the fixture's original receiver assertion.
    expect(await signer.nip04!.encrypt('peer', 'text', boundary)).toBe('peer:text');
    expect(await signer.nip44!.decrypt('peer', 'text', boundary)).toBe('text:peer');
    expect(reads).toBe(0);
  });

  it('keeps captured methods when provider and family methods are replaced', async () => {
    const { provider, boundary, sign } = fixture(); const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    const replacement = vi.fn(() => { throw new Error('replacement-called'); });
    provider.signEvent = replacement; provider.nip04.encrypt = replacement; provider.nip44.decrypt = replacement;
    setProvider({ signEvent: replacement });
    await signer.signEvent(template, boundary);
    expect(await signer.nip04!.encrypt('peer', 'text', boundary)).toBe('peer:text');
    expect(await signer.nip44!.decrypt('peer', 'text', boundary)).toBe('text:peer');
    expect(sign).toHaveBeenCalledOnce(); expect(replacement).not.toHaveBeenCalled();
  });

  it('a refused boundary prevents every sign and crypto provider start', async () => {
    const { provider, sign } = fixture(); const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    const refused: SignerEffectBoundary = { start: async () => { throw new Error('custody-refused'); } };
    await expect(signer.signEvent(template, refused)).rejects.toThrow('custody-refused');
    for (const family of [signer.nip04!, signer.nip44!]) for (const method of ['encrypt', 'decrypt'] as const)
      await expect(family[method]('peer', 'text', refused)).rejects.toThrow('custody-refused');
    expect(sign).not.toHaveBeenCalled();
    expect(provider.nip04.encrypt).not.toHaveBeenCalled(); expect(provider.nip44.decrypt).not.toHaveBeenCalled();
  });

  it('retries a transient provider error through a fresh boundary with the same callable', async () => {
    vi.useFakeTimers(); const { provider, sign, boundary } = fixture();
    sign.mockRejectedValueOnce(new Error('Request failed'));
    const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    const spy = vi.spyOn(boundary, 'start'); const work = signer.signEvent(template, boundary);
    await vi.advanceTimersByTimeAsync(1);
    provider.signEvent = vi.fn(() => { throw new Error('changed-method'); });
    await vi.advanceTimersByTimeAsync(250); await work;
    expect(sign).toHaveBeenCalledTimes(2); expect(spy).toHaveBeenCalledTimes(2); expect(provider.signEvent).not.toHaveBeenCalled();
  });

  it('close revokes a queued retry without calling the provider again', async () => {
    vi.useFakeTimers(); const { sign, boundary } = fixture(); sign.mockRejectedValueOnce(new Error('Request failed'));
    const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    const work = signer.signEvent(template, boundary); const refused = expect(work).rejects.toThrow('nip07-signer-closed');
    await vi.advanceTimersByTimeAsync(1); await signer.close(); await vi.advanceTimersByTimeAsync(250); await refused;
    expect(sign).toHaveBeenCalledOnce();
    await expect(signer.nip44!.encrypt('peer', 'text', boundary)).rejects.toThrow('nip07-signer-closed');
  });

  it('close revokes a boundary-delayed call', async () => {
    const { sign } = fixture(); const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    let invoke!: () => void;
    const delayed: SignerEffectBoundary = { start: effect => new Promise((resolve, reject) => { invoke = () => { effect().then(resolve, reject); }; }) };
    const work = signer.signEvent(template, delayed); const refused = expect(work).rejects.toThrow('nip07-signer-closed');
    await signer.close(); invoke(); await refused; expect(sign).not.toHaveBeenCalled();
  });

  it('joins a started provider result after close without granting later calls', async () => {
    const { provider } = fixture(); let resolve!: (event: NostrEvent) => void;
    const raw = { ...template, pubkey: key } as NostrEvent;
    provider.signEvent = vi.fn(() => new Promise<NostrEvent>(yes => { resolve = yes; }));
    const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    let settled = false;
    const work = signer.signEvent(template, { start: effect => effect() }).finally(() => { settled = true; });
    await signer.close(); expect(settled).toBe(false); resolve(raw);
    expect(await work).toBe(raw);
    await expect(signer.signEvent(template)).rejects.toThrow('nip07-signer-closed');
    expect(provider.signEvent).toHaveBeenCalledOnce();
  });

  it('preserves provider result identity and refuses a substituted boundary result', async () => {
    const { provider } = fixture(); const raw = { ...template, pubkey: key } as NostrEvent;
    provider.signEvent = vi.fn(async () => raw);
    const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    expect(await signer.signEvent(template, { start: effect => effect() })).toBe(raw);
    const substitute: SignerEffectBoundary = { start: async effect => { await effect(); return {} as never; } };
    await expect(signer.signEvent(template, substitute)).rejects.toThrow('signer-effect-result-substituted');
  });

  it('does not retry a boundary rejection that resembles a transient provider error', async () => {
    const { sign } = fixture(); const signer = await createPinnedNip07SignerWithDiscoveryBoundary(discovery);
    const start = vi.fn(async () => { throw new Error('Request failed'); });
    await expect(signer.signEvent(template, { start })).rejects.toThrow('Request failed');
    expect(start).toHaveBeenCalledOnce(); expect(sign).not.toHaveBeenCalled();
  });

  it('binds the global feature marker to the actual additive factory', () => {
    expect(HEADLESS_NIP07_PINNED_PROVIDER_CALLS).toBe(1);
    const global = (window as unknown as { Signet: Record<string, unknown> }).Signet;
    expect(global.HEADLESS_NIP07_PINNED_PROVIDER_CALLS).toBe(1);
    const original = global.createPinnedNip07SignerWithDiscoveryBoundary;
    try {
      global.createPinnedNip07SignerWithDiscoveryBoundary = vi.fn();
      global.HEADLESS_NIP07_PINNED_PROVIDER_CALLS = 1;
      expect(global.HEADLESS_NIP07_PINNED_PROVIDER_CALLS).toBeUndefined();
    } finally { global.createPinnedNip07SignerWithDiscoveryBoundary = original; }
    expect(global.HEADLESS_NIP07_PINNED_PROVIDER_CALLS).toBe(1);
  });

  it('refuses discovery without preflight and malformed captured crypto methods', async () => {
    fixture(); await expect(createPinnedNip07SignerWithDiscoveryBoundary({ discoveryPreflightBoundary: 1,
      start: (_prepare, effect) => effect() })).rejects.toThrow('nip07-discovery-not-prepared');
    const { provider } = fixture(); Reflect.set(provider.nip44, 'encrypt', undefined);
    await expect(createPinnedNip07SignerWithDiscoveryBoundary(discovery)).rejects.toThrow('invalid-nip07-provider-callables');
  });
});
