import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('signet-verify', async original => ({ ...(await original<typeof import('signet-verify')>()), waitForAuthResponse: vi.fn() }));
vi.mock('../src/signers.js', async original=>({...await original<typeof import('../src/signers.js')>(),createBunkerSigner:vi.fn(),createBunkerSignerFromNostrConnect:vi.fn()}));
vi.mock('qrcode', () => ({ default: { toCanvas: vi.fn(async () => {}) } }));
import { createBunkerSigner, createBunkerSignerFromNostrConnect } from '../src/signers.js';
import { bytesToHexLocal, loadOrCreatePersistentClientSkFromStorage, clearPendingRelayAuth } from '../src/storage.js';
import { waitForAuthResponse } from 'signet-verify';
import { login, restoreSession, handleRedirectCallback } from '../src/signet-login.js';
import { loadSessionFromStorage, saveSessionToStorage, clearSessionFromStorage, loadPendingRelayAuth, loadPendingRedirectFromStorage, savePendingRelayAuth, savePendingRedirectToStorage } from '../src/storage.js';
import { startRedirect } from '../src/redirect.js';
import { STORAGE_KEYS, type SignetStorage } from '../src/types.js';
import { makeAuthEvent } from './helpers/auth-event.js';
const challenge = 'a'.repeat(64);
function store() {
  const data = new Map<string, string>();
  const adapter = {
    required: true,
    compareAndSetItem: vi.fn(async (key: string, expected: string | null, value: string | null) => {
      if((data.get(key) ?? null) !== expected) return false;
      if(value===null) data.delete(key); else data.set(key,value); return true;
    }),
    getItem: vi.fn(async (key: string) => data.get(key) ?? null),
    setItem: vi.fn(async (key: string, value: string) => { data.set(key, value); }),
    removeItem: vi.fn(async (key: string) => { data.delete(key); }),
    getItems: vi.fn(async (keys: readonly string[]) => Object.fromEntries(keys.map(key => [key, data.get(key) ?? null]))),
    setItems: vi.fn(async (changes: Readonly<Record<string, string | null>>) => {
      for(const [key, value] of Object.entries(changes)) { if(value === null) data.delete(key); else data.set(key, value); }
    }),
  } satisfies SignetStorage;
  return { data, adapter };
}
function deletions(adapter: ReturnType<typeof store>['adapter']) { return adapter.compareAndSetItem.mock.calls.filter(call=>call[2]===null); }
function holdDeletion(adapter: ReturnType<typeof store>['adapter'], receipt: ReturnType<typeof deferred>) {
  const commit=adapter.compareAndSetItem.getMockImplementation()!;
  adapter.compareAndSetItem.mockImplementation(async (key,expected,value)=>{ if(value===null) await receipt.promise; return commit(key,expected,value); });
}
function deferred() { let yes!: () => void, no!: (error: Error) => void; const promise = new Promise<void>((resolve, reject) => { yes = resolve; no = reject; }); return { promise, yes, no }; }
function persistedPageShow() { const event = new Event('pageshow'); Object.defineProperty(event, 'persisted', {value: true}); window.dispatchEvent(event); }
function session() { const event = makeAuthEvent({ challenge, origin: window.location.origin }); return { pubkey: event.pubkey, method: 'nip07' as const, authEventJson: JSON.stringify(event) }; }
function relay(storage: SignetStorage, method: 'remote-signet' | 'local-signet' = 'remote-signet') { return login({ appName:'Test', challenge, theme:'dark', preferredMethod:method, storage, relayUrl:'wss://relay.test' }); }
beforeEach(() => {
  localStorage.clear(); window.history.replaceState(null, '', '/'); document.body.innerHTML = '';
  HTMLDialogElement.prototype.showModal = function() { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function() { this.removeAttribute('open'); };
  vi.mocked(createBunkerSigner).mockReset(); vi.mocked(createBunkerSignerFromNostrConnect).mockReset();
  vi.mocked(waitForAuthResponse).mockReset().mockImplementation(() => new Promise(() => {}));
  vi.spyOn(window, 'open').mockReturnValue(null);
});
afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML=''; });
describe('atomic required sessions', () => {
  it('replaces and clears whole sessions in single acknowledged batches without individual field effects', async () => {
    const {adapter, data} = store(); const initial = session();
    await saveSessionToStorage({...initial, method:'bunker', bunkerUri:`bunker://${initial.pubkey}?relay=wss%3A%2F%2Frelay.test`, bunkerClientSkHex:'03'.repeat(32), displayName:'Old'}, adapter);
    const old = await loadSessionFromStorage(adapter); const receipt = deferred();
    const commit = adapter.setItems.getMockImplementation()!;
    adapter.setItems.mockImplementationOnce(async changes => { expect(Object.isFrozen(changes)).toBe(true); await receipt.promise; await commit(changes); });
    let returned = false; const pending = saveSessionToStorage(initial, adapter).then(() => { returned=true; });
    await vi.waitFor(() => expect(adapter.setItems).toHaveBeenCalledTimes(2));
    expect(await loadSessionFromStorage(adapter)).toEqual(old); expect(returned).toBe(false);
    receipt.yes(); await pending; expect(await loadSessionFromStorage(adapter)).toEqual(initial);
    expect(data.has(STORAGE_KEYS.bunkerClientSk)).toBe(false); expect(data.has(STORAGE_KEYS.displayName)).toBe(false);
    data.set(STORAGE_KEYS.pendingRelayAuth, 'private'); data.set(STORAGE_KEYS.pendingRedirect, 'redirect');
    await clearSessionFromStorage(adapter); expect(data.size).toBe(0);
    expect(adapter.setItems).toHaveBeenCalledTimes(3); expect(adapter.setItem).not.toHaveBeenCalled(); expect(adapter.removeItem).not.toHaveBeenCalled(); expect(adapter.getItem).not.toHaveBeenCalled();
  });
  it('does not fall back to individual reads/writes when the batch contract is missing', async () => {
    const {adapter} = store(); const incomplete = {...adapter, getItems:undefined, setItems:undefined};
    await expect(loadSessionFromStorage(incomplete)).rejects.toThrow('atomic-read-unavailable');
    await expect(saveSessionToStorage(session(), incomplete)).rejects.toThrow('atomic-write-unavailable');
    await expect(relay(incomplete)).rejects.toThrow('atomic-session-unavailable');
    expect(adapter.getItem).not.toHaveBeenCalled(); expect(adapter.setItem).not.toHaveBeenCalled(); expect(waitForAuthResponse).not.toHaveBeenCalled();
  });
  it('preserves an existing coherent session after a rejected atomic replacement', async () => {
    const {adapter, data} = store(); await saveSessionToStorage(session(), adapter); const before = [...data];
    adapter.setItems.mockRejectedValueOnce(new Error('held'));
    await expect(saveSessionToStorage({...session(), displayName:'New'}, adapter)).rejects.toThrow('held'); expect([...data]).toEqual(before);
  });
  for (const value of [{}, Object.fromEntries(Object.values(STORAGE_KEYS).map(key=>[key,null]))]) it('rejects incomplete or overbroad snapshots without deleting data', async () => {
    const {adapter} = store(); adapter.getItems.mockResolvedValueOnce(value);
    await expect(loadSessionFromStorage(adapter)).rejects.toThrow('invalid-snapshot'); expect(adapter.setItems).not.toHaveBeenCalled();
  });
  for(const malformed of ['00'.repeat(32), 'ff'.repeat(32), 'garbage', '']) it(`holds malformed bunker keys (${malformed.slice(0,4)}) before restore can clear or reconnect`, async () => {
    const {adapter,data} = store(); const initial = session(); await saveSessionToStorage(initial,adapter);
    data.set(STORAGE_KEYS.method,'bunker'); data.set(STORAGE_KEYS.bunkerUri,`bunker://${initial.pubkey}?relay=wss%3A%2F%2Frelay.test`); data.set(STORAGE_KEYS.bunkerClientSk,malformed); const before=[...data];
    await expect(restoreSession({storage:adapter})).rejects.toThrow('invalid-session'); expect([...data]).toEqual(before); expect(adapter.setItems).toHaveBeenCalledOnce();
  });
  it('holds corrupted stored auth proofs and method/credential mismatches', async () => {
    const {adapter,data}=store(); await saveSessionToStorage(session(),adapter);
    data.set(STORAGE_KEYS.authEvent,JSON.stringify({...JSON.parse(session().authEventJson), sig:'0'.repeat(128)}));
    await expect(loadSessionFromStorage(adapter)).rejects.toThrow('invalid-session');
    data.set(STORAGE_KEYS.authEvent,session().authEventJson); data.set(STORAGE_KEYS.bunkerClientSk,'03'.repeat(32));
    await expect(loadSessionFromStorage(adapter)).rejects.toThrow('invalid-session');
  });
});
describe('required pending records and cleanup', () => {
  for(const raw of ['', '{broken', 'null', '{}']) it(`holds malformed pending state (${raw}) without replacement or fresh relay entropy`, async () => {
    const {adapter,data}=store(); data.set(STORAGE_KEYS.pendingRelayAuth,raw); data.set(STORAGE_KEYS.pendingRedirect,raw);
    const random=vi.spyOn(crypto,'getRandomValues');
    await expect(loadPendingRelayAuth(adapter)).rejects.toThrow('invalid-pending-relay');
    await expect(loadPendingRedirectFromStorage(adapter)).rejects.toThrow('invalid-pending-redirect');
    await expect(relay(adapter)).rejects.toThrow('invalid-pending-relay');
    await expect(savePendingRedirectToStorage({challenge, origin:window.location.origin, appName:'Test', createdAt:Date.now()},adapter)).rejects.toThrow('invalid-pending-redirect');
    expect(random).not.toHaveBeenCalled(); expect(adapter.setItem).not.toHaveBeenCalled(); expect(adapter.removeItem).not.toHaveBeenCalled(); expect(data.get(STORAGE_KEYS.pendingRelayAuth)).toBe(raw); expect(data.get(STORAGE_KEYS.pendingRedirect)).toBe(raw);
  });
  it('holds a zero-scalar pending relay key and a different existing request binding', async () => {
    const {adapter,data}=store(); const record={challenge,origin:window.location.origin,appName:'Test',relayUrl:'wss://relay.test',sessionSkHex:'00'.repeat(32),issuedAt:Math.floor(Date.now()/1000)};
    data.set(STORAGE_KEYS.pendingRelayAuth,JSON.stringify(record)); await expect(relay(adapter)).rejects.toThrow('invalid-pending-relay');
    data.set(STORAGE_KEYS.pendingRelayAuth,JSON.stringify({...record,sessionSkHex:'03'.repeat(32),origin:'https://other.test'}));
    await expect(relay(adapter)).rejects.toThrow('binding-mismatch'); expect(adapter.setItem).not.toHaveBeenCalled();
  });
  for(const method of ['remote-signet','local-signet'] as const) for(const exit of ['success','back','cancel','native-cancel','browser-back','denied','expired','aborted']) it(`${method} waits for deletion on ${exit} and propagates rejection`, async () => {
    const {adapter,data}=store(), receipt=deferred(); holdDeletion(adapter, receipt);
    const event=makeAuthEvent({challenge,origin:window.location.origin});
    let deliver!: (value: never)=>void, refuse!: (error:Error)=>void;
    vi.mocked(waitForAuthResponse).mockImplementation(()=>new Promise((yes,no)=>{deliver=yes;refuse=no;}));
    let settled=false; const pending=relay(adapter,method); const observed=pending.then(value=>{settled=true;return value;},error=>{settled=true;throw error;});
    const outcome=expect(observed).rejects.toThrow('deletion held');
    await vi.waitFor(()=>expect(waitForAuthResponse).toHaveBeenCalledOnce());
    if(exit==='success') deliver({pubkey:event.pubkey,authEvent:event} as never);
    else if(exit==='back'||exit==='cancel') document.querySelector<HTMLButtonElement>(`[data-action="${exit}"]`)!.click();
    else if(exit==='native-cancel') document.querySelector('dialog')!.dispatchEvent(new Event('cancel',{cancelable:true}));
    else if(exit==='browser-back') persistedPageShow();
    else refuse(Object.assign(new Error(exit),{code:exit}));
    await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1)); expect(settled).toBe(false); expect(data.has(STORAGE_KEYS.pendingRelayAuth)).toBe(true); expect(adapter.setItems).not.toHaveBeenCalled();
    receipt.no(new Error('deletion held')); await outcome; expect(adapter.setItems).not.toHaveBeenCalled();
  });
  it('reports success only after pending deletion and the atomic session receipt', async()=>{
    const {adapter,data}=store(), deletion=deferred(), retention=deferred();
    holdDeletion(adapter,deletion); const commit=adapter.setItems.getMockImplementation()!; adapter.setItems.mockImplementation(async changes=>{await retention.promise;await commit(changes);});
    const event=makeAuthEvent({challenge,origin:window.location.origin}); vi.mocked(waitForAuthResponse).mockResolvedValue({pubkey:event.pubkey,authEvent:event} as never);
    let settled=false; const pending=relay(adapter).then(value=>{settled=true;return value;});
    await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1)); expect(settled).toBe(false); expect(adapter.setItems).not.toHaveBeenCalled(); deletion.yes();
    await vi.waitFor(()=>expect(adapter.setItems).toHaveBeenCalledOnce()); expect(settled).toBe(false); retention.yes(); expect((await pending)?.pubkey).toBe(event.pubkey); expect(data.has(STORAGE_KEYS.pendingRelayAuth)).toBe(false);
  });
  for(const action of ['back','cancel']) it(`revokes an approved result when ${action} arrives during unknown deletion`,async()=>{
    const {adapter,data}=store(),receipt=deferred();holdDeletion(adapter,receipt);
    const event=makeAuthEvent({challenge,origin:window.location.origin});vi.mocked(waitForAuthResponse).mockResolvedValue({pubkey:event.pubkey,authEvent:event} as never);
    const pending=relay(adapter);await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1));document.querySelector<HTMLButtonElement>(`[data-action="${action}"]`)!.click();receipt.yes();
    await expect(pending).resolves.toBeNull();expect(adapter.setItems).not.toHaveBeenCalled();expect(deletions(adapter)).toHaveLength(1);
  });
  it('joins terminal-error cleanup when Cancel arrives while deletion is unknown',async()=>{
    const {adapter}=store(), receipt=deferred(); holdDeletion(adapter,receipt);
    vi.mocked(waitForAuthResponse).mockRejectedValue(Object.assign(new Error('denied'),{code:'denied'})); const pending=relay(adapter);const outcome=expect(pending).rejects.toThrow('held');
    await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1));document.querySelector<HTMLButtonElement>('[data-action="cancel"]')!.click();receipt.no(new Error('held'));await outcome;expect(deletions(adapter)).toHaveLength(1);
  });
  it('rejects BFCache cancellation when same-tab redirect deletion fails',async()=>{
    const {adapter,data}=store(),receipt=deferred();holdDeletion(adapter,receipt);
    const pending=startRedirect({appName:'Test',challenge,origin:window.location.origin,signetAppOrigin:window.location.origin+'/#',storage:adapter});const outcome=expect(pending).rejects.toThrow('held');
    await vi.waitFor(()=>expect(data.has(STORAGE_KEYS.pendingRedirect)).toBe(true)); await Promise.resolve();persistedPageShow();await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1));receipt.no(new Error('held'));await outcome;expect(data.has(STORAGE_KEYS.pendingRedirect)).toBe(true);
  });
  it('propagates callback deletion failure without exposing a session', async()=>{
    const {adapter,data}=store();data.set(STORAGE_KEYS.pendingRedirect,JSON.stringify({challenge,origin:window.location.origin,appName:'Test',createdAt:Date.now()}));const receipt=deferred();holdDeletion(adapter,receipt);receipt.no(new Error('held'));void receipt.promise.catch(()=>{});
    window.history.replaceState(null,'','/?error=denied');await expect(handleRedirectCallback({storage:adapter})).rejects.toThrow('held');expect(adapter.setItems).not.toHaveBeenCalled();
  });
  it('waits for expired-state deletion before any replacement can be generated',async()=>{
    const {adapter,data}=store(),receipt=deferred();data.set(STORAGE_KEYS.pendingRelayAuth,JSON.stringify({challenge,origin:window.location.origin,appName:'Test',relayUrl:'wss://relay.test',sessionSkHex:'03'.repeat(32),issuedAt:Math.floor(Date.now()/1000)-400}));holdDeletion(adapter,receipt);
    const random=vi.spyOn(crypto,'getRandomValues');const pending=relay(adapter);const outcome=expect(pending).rejects.toThrow('held');await vi.waitFor(()=>expect(deletions(adapter)).toHaveLength(1));expect(random).not.toHaveBeenCalled();receipt.no(new Error('held'));await outcome;expect(random).not.toHaveBeenCalled();expect(adapter.setItem).not.toHaveBeenCalled();
  });
});


describe('atomic client keys and captured pending custody',()=>{
  it('concurrent first uses return the same retained key; the losing candidate cannot escape',async()=>{
    const {adapter,data}=store();const generated:Uint8Array[]=[];const native=crypto.getRandomValues.bind(crypto);vi.spyOn(crypto,'getRandomValues').mockImplementation(array=>{const result=native(array);generated.push(array as Uint8Array);return result;});
    const [a,b]=await Promise.all([loadOrCreatePersistentClientSkFromStorage(adapter),loadOrCreatePersistentClientSkFromStorage(adapter)]);
    expect(bytesToHexLocal(a)).toBe(data.get(STORAGE_KEYS.clientSk));expect(bytesToHexLocal(b)).toBe(bytesToHexLocal(a));expect(adapter.compareAndSetItem).toHaveBeenCalledTimes(2);expect(adapter.setItem).not.toHaveBeenCalled();expect(generated.some(key=>key.every(byte=>byte===0))).toBe(true);a.fill(0);b.fill(0);
  });
  it('keeps a client key private while an already-applied CAS receipt is unknown',async()=>{
    const {adapter,data}=store(),receipt=deferred();const commit=adapter.compareAndSetItem.getMockImplementation()!;adapter.compareAndSetItem.mockImplementation(async(key,expected,value)=>{const result=await commit(key,expected,value);await receipt.promise;return result;});
    let returned=false;const pending=loadOrCreatePersistentClientSkFromStorage(adapter).then(key=>{returned=true;return key;});await vi.waitFor(()=>expect(data.has(STORAGE_KEYS.clientSk)).toBe(true));expect(returned).toBe(false);receipt.yes();const key=await pending;expect(bytesToHexLocal(key)).toBe(data.get(STORAGE_KEYS.clientSk));key.fill(0);
  });
  it('preserves a newer pending record when an old captured deletion mismatches',async()=>{
    const {adapter,data}=store();const a={challenge,origin:window.location.origin,appName:'Test',relayUrl:'wss://relay.test',sessionSkHex:'03'.repeat(32),issuedAt:Math.floor(Date.now()/1000)};
    await savePendingRelayAuth(a,adapter);const captured=await loadPendingRelayAuth(adapter);const newer=JSON.stringify({...a,challenge:'b'.repeat(64)});data.set(STORAGE_KEYS.pendingRelayAuth,newer);
    await expect(clearPendingRelayAuth(adapter,captured)).rejects.toThrow('pending-conflict');expect(data.get(STORAGE_KEYS.pendingRelayAuth)).toBe(newer);
  });
  it('concurrent pending creators cannot overwrite an acknowledged request',async()=>{
    const {adapter,data}=store();const a={challenge,origin:window.location.origin,appName:'Test',relayUrl:'wss://relay.test',sessionSkHex:'03'.repeat(32),issuedAt:Math.floor(Date.now()/1000)},b={...a,challenge:'b'.repeat(64)};
    const outcomes=await Promise.allSettled([savePendingRelayAuth(a,adapter),savePendingRelayAuth(b,adapter)]);expect(outcomes.filter(result=>result.status==='fulfilled')).toHaveLength(1);expect(outcomes.filter(result=>result.status==='rejected')).toHaveLength(1);expect(data.get(STORAGE_KEYS.pendingRelayAuth)).toBe(JSON.stringify(a));
  });
  it('rejects the memory-only nsec route and hides it in the required picker',async()=>{
    const {adapter}=store();await expect(login({appName:'Test',preferredMethod:'nsec',storage:adapter})).rejects.toThrow('nsec-is-memory-only');
    const pending=login({appName:'Test',theme:'dark',storage:adapter});await vi.waitFor(()=>expect(document.querySelector('dialog')).not.toBeNull());expect(document.querySelector('[data-choice="nsec"]')).toBeNull();document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')!.click();await expect(pending).resolves.toBeNull();expect(adapter.compareAndSetItem).not.toHaveBeenCalled();
  });
});
describe('required pairing cancellation owns and joins work',()=>{
  function pairing(adapter:SignetStorage,method:'bunker'|'nostrconnect'){return login({appName:'Test',challenge,theme:'dark',preferredMethod:method,storage:adapter,relayUrl:'wss://relay.test'});}
  async function paste(){await vi.waitFor(()=>expect(document.querySelector('#signet-login-bunker-input')).not.toBeNull());(document.querySelector('#signet-login-bunker-input') as HTMLTextAreaElement).value=`bunker://${session().pubkey}?relay=wss%3A%2F%2Frelay.test`;document.querySelector<HTMLButtonElement>('[data-action="connect"]')!.click();}
  function nativeCancel(){document.querySelector('dialog')!.dispatchEvent(new Event('cancel',{cancelable:true}));}
  for(const method of ['bunker','nostrconnect'] as const) for(const rejects of [false,true]) it(`${method} joins native cancel during key custody (reject=${rejects})`,async()=>{
    const {adapter}=store(),receipt=deferred();const commit=adapter.compareAndSetItem.getMockImplementation()!;adapter.compareAndSetItem.mockImplementation(async(key,expected,value)=>{await receipt.promise;return commit(key,expected,value);});
    let settled=false;const pending=pairing(adapter,method);const observed=pending.then(value=>{settled=true;return value;},error=>{settled=true;throw error;});const outcome=rejects?expect(observed).rejects.toThrow('held'):expect(observed).resolves.toBeNull();if(method==='bunker')await paste();await vi.waitFor(()=>expect(adapter.compareAndSetItem).toHaveBeenCalledOnce());nativeCancel();await Promise.resolve();expect(settled).toBe(false);if(rejects)receipt.no(new Error('held'));else receipt.yes();await outcome;expect(createBunkerSigner).not.toHaveBeenCalled();expect(createBunkerSignerFromNostrConnect).not.toHaveBeenCalled();expect(adapter.setItems).not.toHaveBeenCalled();
  });
  for(const method of ['bunker','nostrconnect'] as const) it(`${method} joins native cancel during connection and closes a late signer`,async()=>{
    const {adapter}=store();let deliver!:(signer:Awaited<ReturnType<typeof createBunkerSigner>>)=>void;const connection=new Promise<Awaited<ReturnType<typeof createBunkerSigner>>>(resolve=>{deliver=resolve;});vi.mocked(createBunkerSigner).mockReturnValue(connection);vi.mocked(createBunkerSignerFromNostrConnect).mockReturnValue(connection);
    let settled=false;const pending=pairing(adapter,method).then(value=>{settled=true;return value;});if(method==='bunker')await paste();const create=method==='bunker'?createBunkerSigner:createBunkerSignerFromNostrConnect;await vi.waitFor(()=>expect(create).toHaveBeenCalledOnce());nativeCancel();await Promise.resolve();expect(settled).toBe(false);
    if(method==='nostrconnect')expect(vi.mocked(createBunkerSignerFromNostrConnect).mock.calls[0][0].abortSignal?.aborted).toBe(true);
    const close=vi.fn(async()=>{});deliver({pubkey:session().pubkey,close} as unknown as Awaited<ReturnType<typeof createBunkerSigner>>);await expect(pending).resolves.toBeNull();expect(close).toHaveBeenCalledOnce();expect(adapter.setItems).not.toHaveBeenCalled();
  });
  it('propagates pasted-bunker retention failure without leaving login pending',async()=>{
    const {adapter}=store();adapter.compareAndSetItem.mockRejectedValue(new Error('held'));const pending=pairing(adapter,'bunker');const outcome=expect(pending).rejects.toThrow('held');await paste();await outcome;expect(createBunkerSigner).not.toHaveBeenCalled();
  });
});
