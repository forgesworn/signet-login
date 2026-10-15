import { afterEach, describe, expect, it, vi } from 'vitest';
import { createNip07SignerWithDiscoveryBoundary, HEADLESS_NIP07_DISCOVERY_BOUNDARY } from '../src/signet-login.js';
import type { Nip07DiscoveryBoundary } from '../src/signet-login.js';

const key = 'ab'.repeat(32);
function gate<T>() { let release!: (value: T) => void; const promise = new Promise<T>(resolve => { release = resolve; }); return { promise, release }; }
function backend() {
  return { getPublicKey: vi.fn(async () => key), signEvent: vi.fn(),
    nip44: { encrypt: vi.fn(), decrypt: vi.fn() } };
}
function boundary() {
  const state = { live: true, native: false, order: [] as string[] };
  const scope: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1,
    async start<T>(prepare: () => void, effect: () => Promise<T>): Promise<T> {
      state.order.push('prepare'); prepare();
      state.order.push('native-check'); if (!state.live) throw Error('custody-held');
      state.native = true;
      let pending: Promise<T>;
      try { pending = effect(); } finally { state.native = false; }
      const value = await pending;
      state.order.push('handoff-check'); if (!state.live) throw Error('custody-held');
      return value;
    } };
  return { state, scope };
}
afterEach(() => { delete window.nostr; vi.restoreAllMocks(); });

describe('two-stage NIP-07 discovery', () => {
  it('reads all provider metadata before native authority and calls captured discovery inside it', async () => {
    const raw = backend(), { state, scope } = boundary(); window.nostr = raw;
    const discovery = raw.getPublicKey;
    for (const field of ['getPublicKey', 'signEvent', 'nip44'] as const) {
      const captured = raw[field];
      Object.defineProperty(raw, field, { configurable: true, get() { expect(state.native).toBe(false); return captured; } });
    }
    discovery.mockImplementation(async function (this: typeof raw) {
      expect(this).toBe(raw); expect(state.native).toBe(true); state.order.push('discovery'); return key.toUpperCase();
    });
    const signer = await createNip07SignerWithDiscoveryBoundary(scope);
    expect(signer.pubkey).toBe(key);
    expect(state.order).toEqual(['prepare', 'native-check', 'discovery', 'handoff-check']);
    expect(discovery).toHaveBeenCalledOnce();
  });

  it('refuses when a provider getter revokes selection during preflight', async () => {
    const raw = backend(), { state, scope } = boundary(); window.nostr = raw;
    const discovery = raw.getPublicKey; let armed = false;
    const original = scope.start;
    scope.start = function <T>(prepare: () => void, effect: () => Promise<T>) { armed = true; return Reflect.apply(original, this, [prepare, effect]); };
    Object.defineProperty(raw, 'getPublicKey', { get() { if (armed) state.live = false; return discovery; } });
    await expect(createNip07SignerWithDiscoveryBoundary(scope)).rejects.toThrow('custody-held');
    expect(discovery).not.toHaveBeenCalled();
  });

  for (const replacement of ['provider', 'discovery', 'signing', 'crypto-object', 'crypto-method'] as const) {
    it(`refuses ${replacement} replacement before delayed preflight without discovering an account`, async () => {
      const raw = backend(), permission = gate<void>(); window.nostr = raw;
      const scope: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1,
        async start<T>(prepare: () => void, effect: () => Promise<T>) { await permission.promise; prepare(); return effect(); } };
      const work = createNip07SignerWithDiscoveryBoundary(scope);
      const refused = expect(work).rejects.toThrow('nip07-discovery-provider-changed');
      if (replacement === 'provider') window.nostr = backend();
      if (replacement === 'discovery') raw.getPublicKey = vi.fn(async () => key);
      if (replacement === 'signing') raw.signEvent = vi.fn();
      if (replacement === 'crypto-object') raw.nip44 = { encrypt: vi.fn(), decrypt: vi.fn() };
      if (replacement === 'crypto-method') raw.nip44.encrypt = vi.fn();
      permission.release(); await refused; expect(raw.getPublicKey).not.toHaveBeenCalled();
    });
  }

  it('rejects an effect invoked without preflight', async () => {
    const raw = backend(); window.nostr = raw;
    const scope: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1, start: (_prepare, effect) => effect() };
    await expect(createNip07SignerWithDiscoveryBoundary(scope)).rejects.toThrow('nip07-discovery-not-prepared');
    expect(raw.getPublicKey).not.toHaveBeenCalled();
  });

  it('revokes retained callbacks after settlement and never repeats discovery', async () => {
    const raw = backend(); window.nostr = raw; let prepareAgain!: () => void, effectAgain!: () => Promise<unknown>;
    const scope: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1,
      async start<T>(prepare: () => void, effect: () => Promise<T>) { prepareAgain = prepare; effectAgain = effect; prepare(); return effect(); } };
    await createNip07SignerWithDiscoveryBoundary(scope);
    expect(prepareAgain).toThrow('nip07-discovery-already-prepared-or-settled');
    expect(effectAgain).toThrow('signer-effect-already-started-or-settled');
    expect(raw.getPublicKey).toHaveBeenCalledOnce();
  });

  it('joins discovery even when the native boundary rejects after starting it', async () => {
    const raw = backend(), result = gate<string>(); raw.getPublicKey.mockImplementation(() => result.promise); window.nostr = raw;
    const scope: Nip07DiscoveryBoundary = { discoveryPreflightBoundary: 1,
      async start<T>(prepare: () => void, effect: () => Promise<T>): Promise<T> { prepare(); void effect(); throw Error('custody-held'); } };
    let settled = false; const work = createNip07SignerWithDiscoveryBoundary(scope);
    void work.then(() => { settled = true; }, () => { settled = true; });
    const refused = expect(work).rejects.toThrow('custody-held');
    await Promise.resolve(); await Promise.resolve(); expect(settled).toBe(false);
    result.release(key); await refused; expect(raw.getPublicKey).toHaveBeenCalledOnce();
  });

  it('rejects provider replacement after the unabortable discovery result', async () => {
    const raw = backend(), result = gate<string>(), { scope } = boundary(); window.nostr = raw;
    raw.getPublicKey.mockImplementation(() => result.promise);
    const work = createNip07SignerWithDiscoveryBoundary(scope), refused = expect(work).rejects.toThrow('nip07-discovery-provider-changed');
    window.nostr = backend(); result.release(key); await refused;
    expect(raw.getPublicKey).toHaveBeenCalledOnce();
  });

  it('cannot leave a positive global marker beside a replaced discovery factory', () => {
    const global = (window as unknown as { Signet: Record<string, unknown> }).Signet;
    expect(HEADLESS_NIP07_DISCOVERY_BOUNDARY).toBe(1); expect(global.HEADLESS_NIP07_DISCOVERY_BOUNDARY).toBe(1);
    const original = global.createNip07SignerWithDiscoveryBoundary;
    try { global.createNip07SignerWithDiscoveryBoundary = vi.fn(); global.HEADLESS_NIP07_DISCOVERY_BOUNDARY = 1;
      expect(global.HEADLESS_NIP07_DISCOVERY_BOUNDARY).toBeUndefined(); }
    finally { global.createNip07SignerWithDiscoveryBoundary = original; }
    expect(global.HEADLESS_NIP07_DISCOVERY_BOUNDARY).toBe(1);
  });
});
