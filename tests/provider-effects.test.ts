import { describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { Nip07Signer, BunkerSignerImpl, DeferredBunkerSigner, LocalSigner, EphemeralSigner } from '../src/signers.js';
import { withProviderEffect } from '../src/effects.js';
import type { EventTemplate, SignerEffectBoundary, SignetAuthEvent } from '../src/types.js';

const secret = new Uint8Array(32).fill(3), person = getPublicKey(secret);
const template = () => ({kind:1,created_at:100,tags:[['t','original']],content:'Original'});
const gate = <T>() => {let release!: (value:T) => void; const promise=new Promise<T>(r=>{release=r}); return {promise,release};};
function boundary() {
  const state={live:true,checks:0};
  const scope: SignerEffectBoundary={async start<T>(work:()=>Promise<T>) {
    state.checks++;if(!state.live)throw Error('native-custody-held');const value=await work();
    if(!state.live)throw Error('native-custody-held');return value;
  }};
  return {state,scope};
}
function backend() {
  return {getPublicKey:vi.fn(async()=>person),signEvent:vi.fn(async(v:EventTemplate)=>finalizeEvent({...v,created_at:v.created_at??100,tags:v.tags??[]},secret)),
    nip04Encrypt:vi.fn(async()=> 'nip04 encrypted'),nip04Decrypt:vi.fn(async()=> 'nip04 plain'),
    nip44Encrypt:vi.fn(async()=> 'nip44 encrypted'),nip44Decrypt:vi.fn(async()=> 'nip44 plain'),
    provisionRendezvous:vi.fn(async()=> 'opaque'),ping:vi.fn(async()=>{}),switchRelays:vi.fn(async()=>true),logout:vi.fn(async()=>{}),close:vi.fn(async()=>{})};
}
describe('per-call provider effect boundary',()=>{
  it('never retries a transient-looking boundary refusal after a successful provider call',async()=>{
    const sign=vi.fn(async(value:EventTemplate)=>finalizeEvent(value as Required<EventTemplate>,secret));let checks=0;
    const scope:SignerEffectBoundary={async start<T>(work:()=>Promise<T>){checks++;await work();throw Error('Request failed')}};
    const signer=new Nip07Signer(person,{getPublicKey:async()=>person,signEvent:sign});
    await expect(signer.signEvent(template(),scope)).rejects.toThrow('Request failed');expect(checks).toBe(1);expect(sign).toHaveBeenCalledOnce();
  });
  it('never retries a transient-looking refusal before any provider was started',async()=>{
    const sign=vi.fn(async(value:EventTemplate)=>finalizeEvent(value as Required<EventTemplate>,secret));let checks=0;
    const scope:SignerEffectBoundary={async start<T>(_work:()=>Promise<T>){checks++;throw Error('Receiving end does not exist')}};
    const signer=new Nip07Signer(person,{getPublicKey:async()=>person,signEvent:sign});
    await expect(signer.signEvent(template(),scope)).rejects.toThrow('Receiving end does not exist');expect(checks).toBe(1);expect(sign).not.toHaveBeenCalled();
  });
  it('freshly checks a transient NIP-07 retry and prevents another provider request after revocation',async()=>{
    const {state,scope}=boundary(),sign=vi.fn(async()=>{state.live=false;throw Error('Receiving end does not exist')});
    const signer=new Nip07Signer(person,{getPublicKey:async()=>person,signEvent:sign});
    await expect(signer.signEvent(template(),scope)).rejects.toThrow('native-custody-held');
    expect(sign).toHaveBeenCalledOnce();expect(state.checks).toBe(2);
  });
  it('a permitted retry receives the original template even if the first provider mutates it',async()=>{
    const {state,scope}=boundary(),seen:EventTemplate[]=[];
    const signer=new Nip07Signer(person,{getPublicKey:async()=>person,signEvent:async value=>{
      seen.push(structuredClone(value));if(seen.length===1){value.content='mutated';value.tags![0]![1]='mutated';throw Error('Request failed')}
      return finalizeEvent(value as Required<EventTemplate>,secret);
    }});
    const event=await signer.signEvent(template(),scope);expect(verifyEvent(event)).toBe(true);
    expect(seen).toEqual([template(),template()]);expect(state.checks).toBe(2);
  });
  for(const method of ['sign','nip04-encrypt','nip04-decrypt','nip44-encrypt','nip44-decrypt'] as const)
    it(`deferred ${method} checks custody after the upgrade and preserves inputs`,async()=>{
      const raw=backend(),upgrade=gate<BunkerSignerImpl|null>(),{state,scope}=boundary();
      const deferred=new DeferredBunkerSigner(person,{} as SignetAuthEvent,upgrade.promise),value=template();
      const work=method==='sign'?deferred.signEvent(value,scope):method==='nip04-encrypt'?deferred.nip04!.encrypt(person,'plain',scope):
        method==='nip04-decrypt'?deferred.nip04!.decrypt(person,'encrypted',scope):method==='nip44-encrypt'?deferred.nip44!.encrypt(person,'plain',scope):deferred.nip44!.decrypt(person,'encrypted',scope);
      const refused=expect(work).rejects.toThrow('native-custody-held');value.content='changed';value.tags[0]![1]='changed';state.live=false;
      upgrade.release(new BunkerSignerImpl(person,raw,'bunker://example',new Uint8Array(32).fill(4)));await refused;
      expect(state.checks).toBe(1);expect(raw.signEvent).not.toHaveBeenCalled();expect(raw.nip04Encrypt).not.toHaveBeenCalled();
      expect(raw.nip04Decrypt).not.toHaveBeenCalled();expect(raw.nip44Encrypt).not.toHaveBeenCalled();expect(raw.nip44Decrypt).not.toHaveBeenCalled();
    });
  it('captures a deferred event before awaiting its signer',async()=>{
    const raw=backend(),upgrade=gate<BunkerSignerImpl|null>(),{scope}=boundary(),value=template();
    const deferred=new DeferredBunkerSigner(person,{} as SignetAuthEvent,upgrade.promise),pending=deferred.signEvent(value,scope);
    value.content='changed';value.tags[0]![1]='changed';upgrade.release(new BunkerSignerImpl(person,raw,'bunker://example',new Uint8Array(32).fill(4)));
    const result=await pending;expect(result.content).toBe('Original');expect(result.tags).toEqual([['t','original']]);expect(verifyEvent(result)).toBe(true);
  });
  for(const implementation of ['extension','bunker','local'] as const) {
    for(const method of ['sign','nip04-encrypt','nip04-decrypt','nip44-encrypt','nip44-decrypt'] as const)
      it(`${implementation} ${method} refuses before provider crypto when the boundary holds`,async()=>{
        const raw=backend(),{state,scope}=boundary();state.live=false;
        const signer=implementation==='local'?new LocalSigner(person,new Uint8Array(secret)):implementation==='bunker'?
          new BunkerSignerImpl(person,raw,'bunker://example',new Uint8Array(32).fill(4)):new Nip07Signer(person,{getPublicKey:async()=>person,signEvent:raw.signEvent,
            nip04:{encrypt:raw.nip04Encrypt,decrypt:raw.nip04Decrypt},nip44:{encrypt:raw.nip44Encrypt,decrypt:raw.nip44Decrypt}});
        expect(signer.providerEffectBoundary).toBe(1);
        const work=method==='sign'?signer.signEvent(template(),scope):method==='nip04-encrypt'?signer.nip04!.encrypt(person,'plain',scope):
          method==='nip04-decrypt'?signer.nip04!.decrypt(person,'encrypted',scope):method==='nip44-encrypt'?signer.nip44!.encrypt(person,'plain',scope):signer.nip44!.decrypt(person,'encrypted',scope);
        await expect(work).rejects.toThrow('native-custody-held');expect(state.checks).toBe(1);
        expect(raw.signEvent).not.toHaveBeenCalled();expect(raw.nip04Encrypt).not.toHaveBeenCalled();expect(raw.nip04Decrypt).not.toHaveBeenCalled();
        expect(raw.nip44Encrypt).not.toHaveBeenCalled();expect(raw.nip44Decrypt).not.toHaveBeenCalled();
        if(implementation==='local')await expect(signer.signEvent(template())).resolves.toMatchObject({pubkey:person,content:'Original'});
      });
  }
  it('preserves original provider this and real local NIP-44 encrypt/decrypt through a boundary',async()=>{
    const {scope,state}=boundary(),signer=new LocalSigner(person,new Uint8Array(secret));
    const ciphertext=await signer.nip44!.encrypt(person,'native-owned plaintext',scope);
    expect(await signer.nip44!.decrypt(person,ciphertext,scope)).toBe('native-owned plaintext');expect(state.checks).toBe(2);
    const raw=backend();raw.nip44Encrypt.mockImplementation(async function(){expect(this).toBe(raw);return'with this'});
    const bunker=new BunkerSignerImpl(person,raw,'bunker://example',new Uint8Array(32).fill(4));
    expect(await bunker.nip44!.encrypt(person,'plain',scope)).toBe('with this');
  });
  it('an omitted boundary retains the existing public API and auth-only does not advertise support',async()=>{
    const signer=new LocalSigner(person,new Uint8Array(secret));expect(verifyEvent(await signer.signEvent(template()))).toBe(true);
    expect(new EphemeralSigner(person,{} as SignetAuthEvent)).not.toHaveProperty('providerEffectBoundary');
  });
  it('does not expose an unsettled provider when the boundary fails after starting it',async()=>{
    const request=gate<string>(),started=gate<void>();let settled=false;
    const scope:SignerEffectBoundary={async start<T>(work:()=>Promise<T>){void work();started.release();throw Error('held after start')}};
    const pending=withProviderEffect(scope,()=>request.promise).finally(()=>{settled=true}),refused=expect(pending).rejects.toThrow('held after start');
    await started.promise;await Promise.resolve();expect(settled).toBe(false);request.release('late');await refused;
  });
  it('a settled boundary cannot retain and invoke a provider callback later',async()=>{
    let escaped!:()=>Promise<unknown>;const effect=vi.fn(async()=> 'value');
    const scope:SignerEffectBoundary={async start<T>(work:()=>Promise<T>){escaped=work;return undefined as T}};
    await expect(withProviderEffect(scope,effect)).rejects.toThrow('signer-effect-not-started');
    expect(()=>escaped()).toThrow('already-started-or-settled');expect(effect).not.toHaveBeenCalled();
  });
  it('rejects a second provider invocation and a substituted result',async()=>{
    const effect=vi.fn(async()=> 'value');
    const twice:SignerEffectBoundary={async start<T>(work:()=>Promise<T>){await work();return work()}};
    await expect(withProviderEffect(twice,effect)).rejects.toThrow('already-started-or-settled');expect(effect).toHaveBeenCalledOnce();
    const substitute:SignerEffectBoundary={async start<T>(work:()=>Promise<T>){await work();return 'other' as T}};
    await expect(withProviderEffect(substitute,effect)).rejects.toThrow('result-substituted');
  });
});
