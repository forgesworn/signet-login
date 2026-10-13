import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { HEADLESS_PROVIDER_EFFECT_BOUNDARY, createNip07Signer, createLoginAuthEvent, createSessionFromSigner, createLocalSignerFromNsec, Nip07Signer } from '../src/signet-login.js';
import type { EventTemplate, NostrEvent, SignerEffectBoundary, SignetSigner } from '../src/types.js';

const secret = new Uint8Array(32).fill(7), pubkey = getPublicKey(secret), challenge = 'ab'.repeat(32);
const options = { appName: 'Protected startup', origin: 'https://consumer.test', challenge };
function gate<T>() { let release!: (value: T) => void; const promise = new Promise<T>(resolve => { release = resolve; }); return { promise, release }; }
function boundary() {
  const state = { live: true, starts: 0 };
  const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) {
    if (!state.live) throw Error('custody-held'); state.starts++;
    const value = await work(); if (!state.live) throw Error('custody-held'); return value;
  } };
  return { state, scope };
}
function backend() {
  return { getPublicKey: vi.fn(async () => pubkey),
    signEvent: vi.fn(async (value: EventTemplate) => finalizeEvent(value as Required<EventTemplate>, secret)),
    nip44: { encrypt: async () => 'encrypted', decrypt: async () => 'plain' } };
}
afterEach(() => { delete window.nostr; vi.restoreAllMocks(); });

describe('initial NIP-07 discovery', () => {
  it('does not leave a positive global contract beside replaced headless methods', () => {
    const global = (window as unknown as { Signet: Record<string, unknown> }).Signet;
    expect(HEADLESS_PROVIDER_EFFECT_BOUNDARY).toBe(1); expect(global.HEADLESS_PROVIDER_EFFECT_BOUNDARY).toBe(1);
    for (const name of ['createNip07Signer', 'createLoginAuthEvent', 'createSessionFromSigner']) {
      const original = global[name];
      try { global[name] = vi.fn(); global.HEADLESS_PROVIDER_EFFECT_BOUNDARY = 1; expect(global.HEADLESS_PROVIDER_EFFECT_BOUNDARY).toBeUndefined(); }
      finally { global[name] = original; }
      expect(global.HEADLESS_PROVIDER_EFFECT_BOUNDARY).toBe(1);
    }
  });
  it('refuses before asking the extension for an account', async () => {
    const raw = backend(), { state, scope } = boundary(); window.nostr = raw; state.live = false;
    await expect(createNip07Signer(scope)).rejects.toThrow('custody-held');
    expect(raw.getPublicKey).not.toHaveBeenCalled();
  });
  it('keeps the captured provider receiver and normalises the account', async () => {
    const raw = backend(), { scope } = boundary(); window.nostr = raw;
    raw.getPublicKey.mockImplementation(async function (this: typeof raw) { expect(this).toBe(raw); return pubkey.toUpperCase(); });
    const signer = await createNip07Signer(scope); expect(signer.pubkey).toBe(pubkey); expect(raw.getPublicKey).toHaveBeenCalledOnce();
  });
  for (const replacement of ['provider', 'discovery', 'signing', 'crypto-object', 'crypto-method'] as const) {
    it(`rejects ${replacement} replacement while waiting for native permission`, async () => {
      const raw = backend(), permitted = gate<void>(); window.nostr = raw;
      const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) { await permitted.promise; return work(); } };
      const work = createNip07Signer(scope), refused = expect(work).rejects.toThrow('nip07-discovery-provider-changed');
      if (replacement === 'provider') window.nostr = backend();
      if (replacement === 'discovery') raw.getPublicKey = vi.fn(async () => pubkey);
      if (replacement === 'signing') raw.signEvent = vi.fn(async value => finalizeEvent(value as Required<EventTemplate>, secret));
      if (replacement === 'crypto-object') raw.nip44 = { ...raw.nip44 };
      if (replacement === 'crypto-method') raw.nip44.encrypt = async () => 'substituted';
      permitted.release(); await refused; expect(raw.getPublicKey).not.toHaveBeenCalled();
    });
  }
  it('refuses provider replacement during the unabortable discovery call', async () => {
    const raw = backend(), answer = gate<string>(), { scope } = boundary(); window.nostr = raw;
    raw.getPublicKey.mockImplementation(() => answer.promise);
    const work = createNip07Signer(scope), refused = expect(work).rejects.toThrow('nip07-discovery-provider-changed');
    window.nostr = backend(); answer.release(pubkey); await refused;
  });
  it('joins an already started discovery even when the boundary throws', async () => {
    const raw = backend(), answer = gate<string>(); window.nostr = raw;
    raw.getPublicKey.mockImplementation(() => answer.promise);
    const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>): Promise<T> { void work(); throw Error('custody-held'); } };
    let settled = false; const work = createNip07Signer(scope); void work.then(() => { settled = true; }, () => { settled = true; });
    await Promise.resolve(); await Promise.resolve(); expect(settled).toBe(false); expect(raw.getPublicKey).toHaveBeenCalledOnce();
    const refused = expect(work).rejects.toThrow('custody-held'); answer.release(pubkey); await refused;
  });
  it('refuses a fabricated discovery result', async () => {
    const raw = backend(); window.nostr = raw;
    const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) { await work(); return 'f'.repeat(64) as T; } };
    await expect(createNip07Signer(scope)).rejects.toThrow('signer-effect-result-substituted');
  });
  it('does not coerce a non-string extension result', async () => {
    const raw = backend(), { scope } = boundary(), coercion = vi.fn(() => pubkey); window.nostr = raw;
    raw.getPublicKey.mockResolvedValue({ toString: coercion } as unknown as string);
    await expect(createNip07Signer(scope)).rejects.toThrow('invalid-pubkey-from-nip07'); expect(coercion).not.toHaveBeenCalled();
  });
});

describe('guarded headless login proof', () => {
  for (const field of ['pubkey', 'method'] as const) {
    it(`returns the captured identity or holds when signer ${field} changes between reads`, async () => {
      // Exercise changes before, during and immediately after handoff without
      // relying on the implementation's number of identity checks.
      for (let transition = 2; transition <= 48; transition++) {
        const raw = backend(), { scope } = boundary(), signer = new Nip07Signer(pubkey, raw); let reads = 0;
        Object.defineProperty(signer, field, { get: () => ++reads >= transition ? (field === 'pubkey' ? 'f'.repeat(64) : 'bunker') : (field === 'pubkey' ? pubkey : 'nip07') });
        let session;
        try { session = await createSessionFromSigner(signer, { ...options, boundary: scope }); }
        catch (error) { expect(String(error)).toMatch(/login-signer-changed|guarded-proof-template/); }
        if (session) {
          expect(session.pubkey).toBe(pubkey); expect(session.pubkey).toBe(session.authEvent.pubkey); expect(session.method).toBe('nip07');
        }
        expect(raw.signEvent.mock.calls.length).toBeLessThanOrEqual(1);
      }
    });
  }
  it('fences generated challenge entropy and returns a detached, frozen session and proof', async () => {
    const raw = backend(), { state, scope } = boundary(), signer = new Nip07Signer(pubkey, raw);
    const session = await createSessionFromSigner(signer, { ...options, challenge: undefined, boundary: scope });
    expect(state.starts).toBe(3); expect(raw.signEvent).toHaveBeenCalledOnce();
    expect(session.authEvent.tags[0]![1]).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(session)).toBe(true); expect(Object.isFrozen(session.authEvent)).toBe(true);
    expect(Object.isFrozen(session.authEvent.tags)).toBe(true); expect(Object.isFrozen(session.authEvent.tags[0])).toBe(true);
    expect(session.signer).toBe(signer);
  });
  it('denies before random challenge generation or signing', async () => {
    const raw = backend(), { state, scope } = boundary(), entropy = vi.spyOn(crypto, 'getRandomValues'); state.live = false;
    await expect(createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, challenge: undefined, boundary: scope })).rejects.toThrow('custody-held');
    expect(entropy).not.toHaveBeenCalled(); expect(raw.signEvent).not.toHaveBeenCalled();
  });
  it('rejects an unsupported signer before entropy or provider work', async () => {
    const raw = backend(), { scope } = boundary(), entropy = vi.spyOn(crypto, 'getRandomValues');
    const signer = { pubkey, method: 'nip07', signEvent: raw.signEvent, capabilities: { canSignEvents: true, hasNip44: false }, close: async () => {} } as SignetSigner;
    await expect(createLoginAuthEvent(signer, { ...options, challenge: undefined, boundary: scope })).rejects.toThrow('signer-effect-boundary-unsupported');
    expect(entropy).not.toHaveBeenCalled(); expect(raw.signEvent).not.toHaveBeenCalled();
  });
  it('captures login options before a waiting decision', async () => {
    const raw = backend(), permitted = gate<void>(), signer = new Nip07Signer(pubkey, raw);
    const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) { await permitted.promise; return work(); } };
    const supplied = { ...options, boundary: scope }, work = createSessionFromSigner(signer, supplied);
    supplied.appName = 'Substituted'; supplied.challenge = 'cd'.repeat(32); supplied.origin = 'https://other.test';
    permitted.release(); const session = await work;
    expect(session.authEvent.tags).toEqual([['challenge', challenge], ['origin', options.origin], ['app', options.appName]]);
  });
  it('refuses a changed signer before the queued signing callback runs', async () => {
    const raw = backend(), permitted = gate<void>(), signer = new Nip07Signer(pubkey, raw);
    const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) { await permitted.promise; return work(); } };
    const work = createLoginAuthEvent(signer, { ...options, boundary: scope }), refused = expect(work).rejects.toThrow('login-signer-changed');
    Object.defineProperty(signer, 'pubkey', { value: 'f'.repeat(64) }); permitted.release(); await refused; expect(raw.signEvent).not.toHaveBeenCalled();
  });
  it('refuses a valid signed proof when the final native handoff is held', async () => {
    const raw = backend(); let starts = 0;
    const scope: SignerEffectBoundary = { async start<T>(work: () => Promise<T>) { if (++starts === 2) throw Error('custody-held'); return work(); } };
    await expect(createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope })).rejects.toThrow('custody-held');
    expect(raw.signEvent).toHaveBeenCalledOnce();
  });
  for (const field of ['content', 'time', 'tag-order', 'tag-value', 'account'] as const) {
    it(`rejects a valid signature over substituted ${field}`, async () => {
      const raw = backend(), { scope } = boundary();
      raw.signEvent.mockImplementation(async value => {
        if (field === 'content') value.content = 'substituted';
        if (field === 'time') value.created_at = value.created_at! - 1;
        if (field === 'tag-order') value.tags!.reverse();
        if (field === 'tag-value') value.tags![0]![1] = 'cd'.repeat(32);
        return finalizeEvent(value as Required<EventTemplate>, field === 'account' ? new Uint8Array(32).fill(8) : secret);
      });
      await expect(createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope })).rejects.toThrow('guarded-proof-template');
    });
  }
  for (const accessor of ['content', 'tag-row', 'tag-part'] as const) {
    it(`rejects a provider ${accessor} accessor without invoking it`, async () => {
      const raw = backend(), { scope } = boundary(), getter = vi.fn(() => 'substituted');
      raw.signEvent.mockImplementation(async value => {
        const event = finalizeEvent(value as Required<EventTemplate>, secret);
        if (accessor === 'content') Object.defineProperty(event, 'content', { get: getter });
        if (accessor === 'tag-row') Object.defineProperty(event.tags, '0', { get: getter });
        if (accessor === 'tag-part') Object.defineProperty(event.tags[0]!, '1', { get: getter });
        return event;
      });
      await expect(createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope })).rejects.toThrow('guarded-proof-template');
      expect(getter).not.toHaveBeenCalled();
    });
  }
  it('copies proof fields without invoking provider toJSON hooks or trusting verification caches', async () => {
    const raw = backend(), { scope } = boundary(), hook = vi.fn(() => { throw Error('provider-hook'); }); let source!: NostrEvent;
    raw.signEvent.mockImplementation(async value => { source = finalizeEvent(value as Required<EventTemplate>, secret); Object.defineProperty(source, 'toJSON', { value: hook }); return source; });
    const proof = await createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope });
    source.tags[0]![1] = 'changed'; source.content = 'changed'; expect(proof.tags[0]![1]).toBe(challenge); expect(proof.content).toBe('');
    expect(hook).not.toHaveBeenCalled(); expect(Reflect.ownKeys(proof)).toHaveLength(7);
  });
  it('rejects a signer that advertises support but skips its boundary', async () => {
    const { scope } = boundary(), signer = createLocalSignerFromNsec('07'.repeat(32));
    signer.signEvent = async value => finalizeEvent(value as Required<EventTemplate>, secret);
    await expect(createLoginAuthEvent(signer, { ...options, boundary: scope })).rejects.toThrow('signer-effect-boundary-not-used');
  });
  it('rejects a forged signature even when its template and account match', async () => {
    const raw = backend(), { scope } = boundary(); raw.signEvent.mockImplementation(async value => ({ ...finalizeEvent(value as Required<EventTemplate>, secret), sig: 'f'.repeat(128) }));
    await expect(createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope })).rejects.toThrow('auth-event-invalid');
  });
  it('captures only the fixed proof fields without enumerating unrelated provider properties', async () => {
    const raw = backend(), { scope } = boundary(), enumerate = vi.fn((): never => { throw Error('unbounded-provider-enumeration'); });
    raw.signEvent.mockImplementation(async value => new Proxy(finalizeEvent(value as Required<EventTemplate>, secret), { ownKeys: enumerate }));
    const proof = await createLoginAuthEvent(new Nip07Signer(pubkey, raw), { ...options, boundary: scope });
    expect(proof.pubkey).toBe(pubkey); expect(enumerate).not.toHaveBeenCalled();
  });
});
