/**
 * Three signer implementations behind one interface.
 *
 *   Nip07Signer       — wraps window.nostr (bark, Alby, nos2x, Flamingo, …)
 *   BunkerSignerImpl  — wraps nostr-tools BunkerSigner (NIP-46 over relay)
 *   EphemeralSigner   — auth-only fallback when only the redirect signature is available
 */
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _DeferredBunkerSigner_binding, _DeferredBunkerSigner_refusal, _DeferredBunkerSigner_closed;
import { withProviderEffect } from './effects.js';
import { parseBunkerInput } from 'nostr-tools/nip46';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { NostrConnect } from 'nostr-tools/kinds';
import { SimplePool } from 'nostr-tools/pool';
import { decode as nip19Decode } from 'nostr-tools/nip19';
import { decrypt as nip49Decrypt } from 'nostr-tools/nip49';
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44';
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from 'nostr-tools/nip04';
/** Returns true if a NIP-07 extension is present on the page. */
export function hasNip07() {
    return typeof window !== 'undefined' && !!window.nostr && typeof window.nostr.signEvent === 'function';
}
export class Nip07Signer {
    constructor(pubkey, provider) {
        this.pubkey = pubkey;
        this.provider = provider;
        this.providerEffectBoundary = 1;
        this.closed = false;
        this.method = 'nip07';
        this.capabilities = { canSignEvents: true, hasNip44: !!provider.nip44 };
        if (provider.nip04) {
            this.nip04 = {
                encrypt: async (peer, pt, boundary) => withProviderEffect(boundary, () => { this.assertActive(); return provider.nip04.encrypt(peer, pt); }),
                decrypt: async (peer, ct, boundary) => withProviderEffect(boundary, () => { this.assertActive(); return provider.nip04.decrypt(peer, ct); }),
            };
        }
        if (provider.nip44) {
            this.nip44 = {
                encrypt: async (peer, pt, boundary) => withProviderEffect(boundary, () => { this.assertActive(); return provider.nip44.encrypt(peer, pt); }),
                decrypt: async (peer, ct, boundary) => withProviderEffect(boundary, () => { this.assertActive(); return provider.nip44.decrypt(peer, ct); }),
            };
        }
    }
    async signEvent(template, boundary) {
        return signNip07Template(template, boundary, () => this.assertActive(), filled => this.provider.signEvent(filled));
    }
    async close() {
        // Revoke this wrapper, including any queued retry. NIP-07 provides no
        // way to disconnect the extension or abort a request already handed to it.
        this.closed = true;
    }
    assertActive() {
        if (this.closed)
            throw new Error('nip07-signer-closed');
    }
}
/** Keep template normalisation, provider-error classification and retry policy
 * identical for the legacy and captured-callable wrappers. */
async function signNip07Template(template, boundary, assertActive, invoke) {
    const filled = {
        kind: template.kind,
        content: template.content,
        created_at: template.created_at ?? Math.floor(Date.now() / 1000),
        tags: (template.tags ?? []).map(tag => [...tag]),
    };
    let providerFailed = false, providerFailure;
    return retryTransientNip07Sign(() => withProviderEffect(boundary, () => {
        assertActive();
        try {
            return invoke({ ...filled, tags: filled.tags.map(tag => [...tag]) }).catch(error => {
                providerFailed = true;
                providerFailure = error;
                throw error;
            });
        }
        catch (error) {
            providerFailed = true;
            providerFailure = error;
            return Promise.reject(error);
        }
    }), error => providerFailed && error === providerFailure);
}
function pinnedNip07Signer(pubkey, provider, signing, nip04, nip44, encrypt04, decrypt04, encrypt44, decrypt44) {
    if (typeof signing !== 'function' ||
        (nip04 !== undefined && (typeof encrypt04 !== 'function' || typeof decrypt04 !== 'function')) ||
        (nip44 !== undefined && (typeof encrypt44 !== 'function' || typeof decrypt44 !== 'function'))) {
        throw new Error('invalid-nip07-provider-callables');
    }
    let closed = false;
    const assertActive = () => { if (closed)
        throw new Error('nip07-signer-closed'); };
    const crypto = (receiver, encrypt, decrypt) => Object.freeze({
        encrypt: (peer, text, boundary) => withProviderEffect(boundary, () => { assertActive(); return Reflect.apply(encrypt, receiver, [peer, text]); }),
        decrypt: (peer, text, boundary) => withProviderEffect(boundary, () => { assertActive(); return Reflect.apply(decrypt, receiver, [peer, text]); }),
    });
    return Object.freeze({
        pubkey, method: 'nip07', providerEffectBoundary: 1, pinnedProviderCalls: 1,
        capabilities: Object.freeze({ canSignEvents: true, hasNip44: nip44 !== undefined }),
        ...(nip04 === undefined ? {} : { nip04: crypto(nip04, encrypt04, decrypt04) }),
        ...(nip44 === undefined ? {} : { nip44: crypto(nip44, encrypt44, decrypt44) }),
        signEvent: (template, boundary) => signNip07Template(template, boundary, assertActive, filled => Reflect.apply(signing, provider, [filled])),
        // Revokes queued calls/retries; NIP-07 cannot abort an already-started call.
        close: async () => { closed = true; },
    });
}
async function retryTransientNip07Sign(sign, providerRejected) {
    try {
        return await sign();
    }
    catch (err) {
        if (!providerRejected(err) || !isTransientNip07Error(err))
            throw err;
        await new Promise(resolve => setTimeout(resolve, 250));
        return sign();
    }
}
function isTransientNip07Error(err) {
    const msg = err instanceof Error ? err.message : String(err);
    return /Request failed|Receiving end does not exist|Extension context invalidated|message port closed|context invalidated/i.test(msg);
}
/** Connects to the page's NIP-07 provider and returns a Nip07Signer.
 * An optional boundary fences account discovery, including its result handoff.
 * It does not authorise later signing or connect any other login method. */
export async function createNip07Signer(boundary) {
    if (!hasNip07())
        throw new Error('no-nip07-provider');
    const provider = window.nostr;
    if (boundary === undefined) {
        const pubkey = await provider.getPublicKey();
        if (!/^[0-9a-f]{64}$/i.test(pubkey))
            throw new Error('invalid-pubkey-from-nip07');
        return new Nip07Signer(pubkey.toLowerCase(), provider);
    }
    return guardedNip07Discovery(provider, (prepare, effect) => withProviderEffect(boundary, () => { prepare(); return effect(); }));
}
/** Restore account discovery through a two-stage native boundary. Provider
 * references are captured before boundary.start; prepare() revalidates them
 * before the caller's final synchronous native decision. The effect only
 * calls captured references. SDK result checks and wrapper construction read
 * metadata afterwards, so the caller must revalidate custody after this
 * entire SDK promise settles. */
export async function createNip07SignerWithDiscoveryBoundary(boundary) {
    if (!hasNip07())
        throw new Error('no-nip07-provider');
    const provider = window.nostr;
    return guardedNip07Discovery(provider, discoveryBoundaryRunner(boundary));
}
/** Opt in to fixed provider callables as well as guarded discovery. Every
 * signing/crypto attempt invokes the captured function with its captured
 * receiver inside the supplied effect boundary. No provider property is
 * looked up by this wrapper after discovery. Callers must still validate
 * native custody and provider identity, and authenticate the returned proof. */
export async function createPinnedNip07SignerWithDiscoveryBoundary(boundary) {
    if (!hasNip07())
        throw new Error('no-nip07-provider');
    const provider = window.nostr;
    return guardedNip07Discovery(provider, discoveryBoundaryRunner(boundary), true);
}
function discoveryBoundaryRunner(boundary) {
    const version = boundary.discoveryPreflightBoundary, start = boundary.start;
    if (version !== 1 || typeof start !== 'function')
        throw new Error('invalid-nip07-discovery-boundary');
    return (prepare, effect) => {
        let attempted = false, prepared = false, settled = false;
        const preflight = () => {
            if (attempted || settled)
                throw new Error('nip07-discovery-already-prepared-or-settled');
            attempted = true;
            prepare();
            prepared = true;
        };
        return withProviderEffect({ start: (once) => Reflect.apply(start, boundary, [preflight, once]) }, () => {
            if (!prepared || settled)
                throw new Error('nip07-discovery-not-prepared');
            return effect();
        }).finally(() => { settled = true; });
    };
}
async function guardedNip07Discovery(provider, run, pinned = false) {
    const discovery = provider.getPublicKey;
    const signing = provider.signEvent;
    const nip04 = provider.nip04, nip44 = provider.nip44;
    const encrypt04 = nip04?.encrypt, decrypt04 = nip04?.decrypt;
    const encrypt44 = nip44?.encrypt, decrypt44 = nip44?.decrypt;
    const check = () => {
        if (window.nostr !== provider || typeof discovery !== 'function' ||
            provider.getPublicKey !== discovery || provider.signEvent !== signing ||
            provider.nip04 !== nip04 || provider.nip44 !== nip44 ||
            nip04?.encrypt !== encrypt04 || nip04?.decrypt !== decrypt04 ||
            nip44?.encrypt !== encrypt44 || nip44?.decrypt !== decrypt44) {
            throw new Error('nip07-discovery-provider-changed');
        }
    };
    const pubkey = await run(check, () => Reflect.apply(discovery, provider, []));
    check();
    if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkey))
        throw new Error('invalid-pubkey-from-nip07');
    return pinned ? pinnedNip07Signer(pubkey.toLowerCase(), provider, signing, nip04, nip44, encrypt04, decrypt04, encrypt44, decrypt44) : new Nip07Signer(pubkey.toLowerCase(), provider);
}
/** Wraps a NIP-46 client with our SignetSigner interface. */
export class BunkerSignerImpl {
    constructor(pubkey, bunker, 
    /** Original bunker URI — kept for persistence/reconnect. */
    bunkerUri, 
    /** The 32-byte client secret key used in this session — kept for reconnect. */
    clientSecretKey) {
        this.pubkey = pubkey;
        this.bunker = bunker;
        this.bunkerUri = bunkerUri;
        this.clientSecretKey = clientSecretKey;
        this.providerEffectBoundary = 1;
        this.method = 'bunker';
        this.capabilities = { canSignEvents: true, hasNip44: true };
        this.nip04 = {
            encrypt: (peer, pt, boundary) => withProviderEffect(boundary, () => bunker.nip04Encrypt(peer, pt)),
            decrypt: (peer, ct, boundary) => withProviderEffect(boundary, () => bunker.nip04Decrypt(peer, ct)),
        };
        this.nip44 = {
            encrypt: (peer, pt, boundary) => withProviderEffect(boundary, () => bunker.nip44Encrypt(peer, pt)),
            decrypt: (peer, ct, boundary) => withProviderEffect(boundary, () => bunker.nip44Decrypt(peer, ct)),
        };
        this.nip46 = {
            ping: () => bunker.ping(),
            switchRelays: () => bunker.switchRelays(),
            logout: () => bunker.logout(),
            provisionRendezvous: (index, nonce, expiresAt) => {
                if (!Number.isSafeInteger(index) || index < 0 || index > 0xffffffff)
                    throw new Error('invalid-rendezvous-index');
                if (!(nonce instanceof Uint8Array) || nonce.length !== 16)
                    throw new Error('invalid-rendezvous-nonce');
                if (!Number.isSafeInteger(expiresAt) || expiresAt < 0)
                    throw new Error('invalid-rendezvous-expiry');
                return bunker.provisionRendezvous(getPublicKey(this.clientSecretKey), index, base64UrlNoPad(nonce), expiresAt);
            },
        };
    }
    async signEvent(template, boundary) {
        // Build the event for the bunker to sign. SET pubkey to the signer's own key
        // rather than stripping it: some signers (e.g. Signet mobile) sign the event
        // as-given and don't fill pubkey themselves, returning `pubkey:""` — which
        // then fails verifyEvent ("event returned from bunker is improperly signed").
        // Providing the key-owner's own pubkey is correct NIP-01 construction and is
        // harmless to bunkers that set it themselves (it's the same value).
        const { pubkey: _omit, ...rest } = template;
        void _omit;
        const filled = {
            pubkey: this.pubkey,
            kind: rest.kind,
            content: rest.content,
            created_at: rest.created_at ?? Math.floor(Date.now() / 1000),
            tags: (rest.tags ?? []).map(tag => [...tag]),
        };
        const verified = await withProviderEffect(boundary, () => this.bunker.signEvent(filled));
        return verified;
    }
    async close() {
        await this.bunker.close();
    }
}
/** Browser and Node compatible, unpadded RFC 4648 URL base64 for the
 * fixed-size public replay nonce. Keeping it here avoids exposing either the
 * NIP-46 client secret or a generic device-key cryptography method. */
function base64UrlNoPad(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let output = '';
    for (let offset = 0; offset < bytes.length; offset += 3) {
        const first = bytes[offset];
        const second = bytes[offset + 1];
        const third = bytes[offset + 2];
        output += alphabet[first >>> 2];
        output += alphabet[((first & 3) << 4) | ((second ?? 0) >>> 4)];
        if (second !== undefined)
            output += alphabet[((second & 15) << 2) | ((third ?? 0) >>> 6)];
        if (third !== undefined)
            output += alphabet[third & 63];
    }
    return output;
}
const NIP46_PAIRING_WAIT_MS = 5 * 60000;
const NIP46_REQUEST_TIMEOUT_MS = 15000;
function errorMessage(err) {
    return err instanceof Error ? err.message : String(err);
}
function emitNostrConnectStatus(onStatus, relays, status) {
    if (!onStatus)
        return;
    try {
        onStatus({
            ...status,
            timestamp: Date.now(),
            relays: [...relays],
        });
    }
    catch {
        // Consumer diagnostics must never break the login flow.
    }
}
function createInstrumentedNostrConnectPool(input) {
    const poolOptions = {
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
function firstFulfilled(promises) {
    if (promises.length === 0)
        return Promise.reject(new Error('no-promises'));
    return new Promise((resolve, reject) => {
        let rejected = 0;
        let lastError;
        for (const promise of promises) {
            promise.then(resolve).catch(err => {
                rejected += 1;
                lastError = err;
                if (rejected === promises.length) {
                    reject(lastError);
                }
            });
        }
    });
}
const NIP46_PUBLISH_RETRY_BUDGET_MS = 20000;
function retryableNip46PublishFailure(error) {
    // nostr-tools uses raw strings for connection establishment failures and
    // Error instances for an explicit relay OK false. Preserve that boundary:
    // transport recovery must never turn a real relay refusal into a retry loop.
    return error === 'connection failure: connection timed out'
        || error === 'connection failure: connection failed';
}
function parseNostrConnectUriForClient(uri, clientPubkey) {
    let parsed;
    try {
        parsed = new URL(uri);
    }
    catch {
        throw new Error('invalid-nostrconnect-uri');
    }
    if (parsed.protocol !== 'nostrconnect:')
        throw new Error('invalid-nostrconnect-uri');
    if (parsed.hostname.toLowerCase() !== clientPubkey.toLowerCase())
        throw new Error('nostrconnect-client-pubkey-mismatch');
    const relays = parsed.searchParams.getAll('relay').map(relay => relay.trim()).filter(Boolean);
    if (relays.length === 0)
        throw new Error('relay-url-required');
    for (const relayUrl of relays) {
        if (!/^wss?:\/\//.test(relayUrl))
            throw new Error('invalid-relay-url');
    }
    const secret = parsed.searchParams.get('secret');
    if (!secret)
        throw new Error('nostrconnect-secret-required');
    return {
        relays: Array.from(new Set(relays)),
        secret,
    };
}
async function waitForNostrConnectApproval(input) {
    const clientPubkey = getPublicKey(input.clientSecretKey);
    const { relays, secret } = parseNostrConnectUriForClient(input.uri, clientPubkey);
    const timeoutMs = input.timeoutMs && input.timeoutMs > 0 ? input.timeoutMs : NIP46_PAIRING_WAIT_MS;
    // Anchored once for the whole flow. Computing this inside subscribe() means a
    // reconnect asks only for events newer than the reconnect — skipping the
    // response already sitting on the relay. Same defect that broke cross-device
    // sign-in before signet-verify 0.5.2.
    const since = Math.floor(Date.now() / 1000) - 60;
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
    let sub;
    let timer;
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (err, signerPubkey) => {
            if (settled)
                return;
            settled = true;
            if (timer !== undefined)
                clearTimeout(timer);
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
                }
                else {
                    emitNostrConnectStatus(input.onStatus, relays, {
                        type: 'error',
                        phase: message === 'nostrconnect-aborted' ? 'abort' : 'pairing',
                        clientPubkey,
                        message,
                        error: err,
                    });
                }
                reject(err);
            }
            else {
                resolve({ signerPubkey: signerPubkey.toLowerCase(), relays, secret });
            }
        };
        if (input.abortSignal?.aborted) {
            finish(new Error('nostrconnect-aborted'));
            return;
        }
        input.abortSignal?.addEventListener('abort', () => finish(new Error('nostrconnect-aborted')), { once: true });
        timer = setTimeout(() => finish(new Error('nostrconnect-timeout')), timeoutMs);
        sub = pool.subscribe(relays, {
            kinds: [NostrConnect],
            '#p': [clientPubkey],
            since,
        }, {
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
                    const response = JSON.parse(nip44Decrypt(event.content, getConversationKey(input.clientSecretKey, event.pubkey)));
                    if (response.result === secret && /^[0-9a-f]{64}$/i.test(event.pubkey)) {
                        emitNostrConnectStatus(input.onStatus, relays, {
                            type: 'response-received',
                            phase: 'pairing',
                            clientPubkey,
                            signerPubkey: event.pubkey.toLowerCase(),
                        });
                        finish(null, event.pubkey);
                    }
                }
                catch {
                    // Ignore unrelated/malformed events addressed to the temporary client pubkey.
                }
            },
            onclose(reasons) {
                if (settled)
                    return;
                emitNostrConnectStatus(input.onStatus, relays, {
                    type: 'error',
                    phase: 'subscription',
                    clientPubkey,
                    message: Array.isArray(reasons) ? reasons.join(',') : 'nostrconnect-subscription-closed',
                });
                finish(new Error('nostrconnect-subscription-closed'));
            },
        });
    });
}
class RobustBunkerClient {
    constructor(clientSecretKey, pointer, onStatus, requestTimeoutMs = NIP46_REQUEST_TIMEOUT_MS, appMetadata) {
        this.clientSecretKey = clientSecretKey;
        this.pointer = pointer;
        this.onStatus = onStatus;
        this.requestTimeoutMs = requestTimeoutMs;
        this.appMetadata = appMetadata;
        this.serial = 0;
        this.closed = false;
        this.idPrefix = Math.random().toString(36).slice(2);
        /**
         * Relay query anchor for this client's whole life, set once at construction.
         * setupSubscription() re-runs on reconnect; a window computed there would skip
         * past a response published while the socket was down.
         */
        this.since = Math.floor(Date.now() / 1000) - 60;
        this.listeners = new Map();
        if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0)
            throw new Error('invalid-request-timeout');
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
    emit(status) {
        emitNostrConnectStatus(this.onStatus, this.relays, {
            clientPubkey: this.clientPubkey,
            signerPubkey: this.pointer.pubkey,
            ...status,
        });
    }
    setupSubscription() {
        if (this.sub || this.closed)
            return;
        this.emit({ type: 'relay-connecting', phase: 'request' });
        const sub = this.pool.subscribe(this.relays, {
            kinds: [NostrConnect],
            authors: [this.pointer.pubkey],
            '#p': [this.clientPubkey],
            since: this.since,
        }, {
            maxWait: NIP46_REQUEST_TIMEOUT_MS,
            onevent: event => this.handleResponseEvent(event),
            onclose: () => {
                if (this.sub === sub)
                    this.sub = undefined;
            },
        });
        this.sub = sub;
    }
    async publishRequest(event) {
        const started = Date.now();
        let delayMs = 250;
        for (;;) {
            try {
                await firstFulfilled(this.pool.publish(this.relays, event, { maxWait: NIP46_REQUEST_TIMEOUT_MS }));
                return;
            }
            catch (error) {
                if (!retryableNip46PublishFailure(error) || Date.now() - started + delayMs > NIP46_PUBLISH_RETRY_BUDGET_MS)
                    throw error;
                this.sub?.close('reconnect after failed publish');
                this.sub = undefined;
                this.pool.close(this.relays);
                await new Promise(resolve => setTimeout(resolve, delayMs));
                if (this.closed)
                    throw new Error('bunker-closed');
                this.setupSubscription();
                delayMs = Math.min(delayMs * 2, 2000);
            }
        }
    }
    handleResponseEvent(event) {
        try {
            const response = JSON.parse(nip44Decrypt(event.content, this.conversationKey));
            if (!response.id)
                return;
            const listener = this.listeners.get(response.id);
            if (!listener)
                return;
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
            }
            else {
                listener.resolve(response.result ?? '');
            }
        }
        catch {
            // Ignore unrelated/malformed events.
        }
    }
    async sendRequest(method, params) {
        if (this.closed)
            throw new Error('this signer is not open anymore, create a new one');
        this.setupSubscription();
        const id = `${this.idPrefix}-${++this.serial}`;
        const content = nip44Encrypt(JSON.stringify({ id, method, params }), this.conversationKey);
        const event = finalizeEvent({
            kind: NostrConnect,
            tags: [['p', this.pointer.pubkey]],
            content,
            created_at: Math.floor(Date.now() / 1000),
        }, this.clientSecretKey);
        const response = new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.listeners.delete(id);
                const err = new Error(`nip46-${method}-timeout`);
                this.emit({
                    type: 'timeout',
                    phase: 'request',
                    method,
                    requestId: id,
                    timeoutMs: this.requestTimeoutMs,
                    message: err.message,
                    error: err,
                });
                reject(err);
            }, this.requestTimeoutMs);
            this.listeners.set(id, { resolve, reject, timer, method });
        });
        this.emit({
            type: 'request-sent',
            phase: 'request',
            method,
            requestId: id,
        });
        void this.publishRequest(event)
            .catch(() => {
            const listener = this.listeners.get(id);
            if (!listener)
                return;
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
    async connect() {
        const params = [this.pointer.pubkey, this.pointer.secret ?? ''];
        if (this.appMetadata?.name || this.appMetadata?.url)
            params.push(JSON.stringify(this.appMetadata));
        await this.sendRequest('connect', params);
    }
    async getPublicKey() {
        if (!this.cachedPubkey) {
            const pubkey = (await this.sendRequest('get_public_key', [])).trim().toLowerCase();
            if (!/^[0-9a-f]{64}$/i.test(pubkey))
                throw new Error('invalid-pubkey-from-bunker');
            this.cachedPubkey = pubkey;
        }
        return this.cachedPubkey;
    }
    async signEvent(event) {
        const signed = JSON.parse(await this.sendRequest('sign_event', [JSON.stringify(event)]));
        if (!verifyEvent(signed))
            throw new Error(`event returned from bunker is improperly signed: ${JSON.stringify(signed)}`);
        return signed;
    }
    async nip04Encrypt(peerPubkey, plaintext) {
        return this.sendRequest('nip04_encrypt', [peerPubkey, plaintext]);
    }
    async nip04Decrypt(peerPubkey, ciphertext) {
        return this.sendRequest('nip04_decrypt', [peerPubkey, ciphertext]);
    }
    async nip44Encrypt(peerPubkey, plaintext) {
        return this.sendRequest('nip44_encrypt', [peerPubkey, plaintext]);
    }
    async nip44Decrypt(peerPubkey, ciphertext) {
        return this.sendRequest('nip44_decrypt', [peerPubkey, ciphertext]);
    }
    async provisionRendezvous(targetDevicePubkey, index, nonce, expiresAt) {
        return this.sendRequest('heartwood_provision_rendezvous', [targetDevicePubkey, index, nonce, expiresAt]);
    }
    async ping() {
        const response = await this.sendRequest('ping', []);
        if (response !== 'pong')
            throw new Error(`result is not pong: ${response}`);
    }
    async switchRelays() {
        try {
            const response = await this.sendRequest('switch_relays', []);
            const parsed = JSON.parse(response);
            if (parsed === null)
                return false;
            if (!Array.isArray(parsed))
                return false;
            const nextRelays = Array.from(new Set(parsed
                .map(relay => typeof relay === 'string' ? relay.trim() : '')
                .filter(relay => /^wss?:\/\//.test(relay))));
            if (nextRelays.length !== parsed.length || nextRelays.length === 0)
                return false;
            const same = JSON.stringify([...nextRelays].sort()) === JSON.stringify([...this.relays].sort());
            if (same)
                return false;
            const previousSub = this.sub;
            this.relays = nextRelays;
            setTimeout(() => previousSub?.close('switch-relays'), 5000);
            this.sub = undefined;
            this.setupSubscription();
            return true;
        }
        catch {
            return false;
        }
    }
    async logout() {
        const response = await this.sendRequest('logout', []);
        if (response !== 'ack')
            throw new Error(`result is not ack: ${response}`);
    }
    async close() {
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
export async function createBunkerSignerFromNostrConnect(input) {
    const { uri, clientSecretKey, abortSignal, timeoutMs, onStatus } = input;
    if (clientSecretKey.length !== 32)
        throw new Error('invalid-client-secret-key');
    const { signerPubkey, relays, secret } = await waitForNostrConnectApproval({
        uri,
        clientSecretKey,
        abortSignal,
        timeoutMs,
        onStatus,
    });
    if (!/^[0-9a-f]{64}$/i.test(signerPubkey))
        throw new Error('invalid-pubkey-from-bunker');
    const normalizedBunkerUri = buildBunkerUriFromNostrConnectUri(uri, signerPubkey);
    const bunker = new RobustBunkerClient(clientSecretKey, {
        pubkey: signerPubkey,
        relays,
        secret,
    }, onStatus, input.requestTimeoutMs);
    let pubkey;
    try {
        pubkey = await bunker.getPublicKey();
        await bestEffortSwitchRelays(bunker);
    }
    catch (err) {
        await bunker.close().catch(() => { });
        throw err;
    }
    return new BunkerSignerImpl(pubkey.toLowerCase(), bunker, normalizedBunkerUri, clientSecretKey);
}
/**
 * Build a NIP-46 `nostrconnect://` URI for the app-initiated flow. The
 * `secret` is echoed back by the bunker on connect so the app can verify
 * it's talking to the right peer; it must be unguessable.
 */
export function buildNostrConnectUri(input) {
    const { clientPubkeyHex, secret } = input;
    if (!/^[0-9a-f]{64}$/i.test(clientPubkeyHex))
        throw new Error('invalid-client-pubkey');
    const relayUrls = input.relayUrls ?? (input.relayUrl ? [input.relayUrl] : []);
    const cleanRelayUrls = relayUrls.map(relay => relay.trim()).filter(Boolean);
    if (cleanRelayUrls.length === 0)
        throw new Error('relay-url-required');
    for (const relayUrl of cleanRelayUrls) {
        if (!/^wss?:\/\//.test(relayUrl))
            throw new Error('invalid-relay-url');
    }
    const params = new URLSearchParams();
    for (const relayUrl of cleanRelayUrls)
        params.append('relay', relayUrl);
    params.set('secret', secret);
    if (input.perms && input.perms.length > 0)
        params.set('perms', input.perms.join(','));
    if (input.appName)
        params.set('name', input.appName);
    if (input.appUrl)
        params.set('url', input.appUrl);
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
export function buildBunkerUriFromNostrConnectUri(nostrConnectUri, signerPubkeyHex) {
    if (!/^[0-9a-f]{64}$/i.test(signerPubkeyHex))
        throw new Error('invalid-signer-pubkey');
    let parsed;
    try {
        parsed = new URL(nostrConnectUri);
    }
    catch {
        throw new Error('invalid-nostrconnect-uri');
    }
    if (parsed.protocol !== 'nostrconnect:')
        throw new Error('invalid-nostrconnect-uri');
    const relays = parsed.searchParams.getAll('relay').map(relay => relay.trim()).filter(Boolean);
    if (relays.length === 0)
        throw new Error('relay-url-required');
    for (const relayUrl of relays) {
        if (!/^wss?:\/\//.test(relayUrl))
            throw new Error('invalid-relay-url');
    }
    const secret = parsed.searchParams.get('secret');
    const params = new URLSearchParams();
    for (const relayUrl of relays)
        params.append('relay', relayUrl);
    if (secret)
        params.set('secret', secret);
    return `bunker://${signerPubkeyHex.toLowerCase()}?${params.toString()}`;
}
export function isBunkerUri(value) {
    return value.trim().toLowerCase().startsWith('bunker://');
}
export function isNostrConnectUri(value) {
    return value.trim().toLowerCase().startsWith('nostrconnect://');
}
export function isSupportedPairingUri(value) {
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
async function raceBunkerHandshake(p, ms, bunker) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
            void bunker.close().catch(() => { });
            reject(new Error('bunker-connect-timeout'));
        }, ms);
    });
    try {
        return await Promise.race([p, timeout]);
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}
async function bestEffortSwitchRelays(bunker, timeoutMs = 1000) {
    let timer;
    try {
        await Promise.race([
            bunker.switchRelays(),
            new Promise(resolve => {
                timer = setTimeout(resolve, timeoutMs);
            }),
        ]);
    }
    catch {
        // Relay migration is advisory; keep the session usable on the current relays.
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}
/**
 * Connect a bunker session from a `bunker://` URI or NIP-05 identifier. Pass
 * `clientSecretKey` to bind a stable client pubkey the signer can auto-approve
 * (see `loadOrCreatePersistentClientSk`); when omitted a fresh ephemeral key is
 * generated, which a per-pubkey-approving bunker will treat as a new,
 * unapproved client.
 */
export async function createBunkerSigner(input) {
    const trimmed = input.uri.trim();
    if (!trimmed)
        throw new Error('empty-bunker-uri');
    const pointer = await parseBunkerInput(trimmed);
    if (!pointer)
        throw new Error('invalid-bunker-uri');
    const sk = input.clientSecretKey ?? generateSecretKey();
    if (sk.length !== 32)
        throw new Error('invalid-client-secret-key');
    const bunker = new RobustBunkerClient(sk, pointer, input.onStatus, input.requestTimeoutMs, { name: input.appName, url: input.appUrl });
    const handshake = (async () => {
        await bunker.connect();
        return bunker.getPublicKey();
    })();
    let pubkey;
    try {
        pubkey = input.timeoutMs && input.timeoutMs > 0
            ? await raceBunkerHandshake(handshake, input.timeoutMs, bunker)
            : await handshake;
    }
    catch (err) {
        await bunker.close().catch(() => { });
        throw err;
    }
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
        await bunker.close().catch(() => { });
        throw new Error('invalid-pubkey-from-bunker');
    }
    await bestEffortSwitchRelays(bunker);
    return new BunkerSignerImpl(pubkey.toLowerCase(), bunker, trimmed, sk);
}
/** Generate a 32-byte secret key. */
export function generateSecretKey() {
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
export class LocalSigner {
    constructor(pubkey, privkey) {
        this.pubkey = pubkey;
        this.privkey = privkey;
        this.providerEffectBoundary = 1;
        this.method = 'nsec';
        this.capabilities = { canSignEvents: true, hasNip44: true };
        this.nip04 = {
            encrypt: (peer, pt, boundary) => withProviderEffect(boundary, async () => nip04Encrypt(this.privkey, peer, pt)),
            decrypt: (peer, ct, boundary) => withProviderEffect(boundary, async () => nip04Decrypt(this.privkey, peer, ct)),
        };
        this.nip44 = {
            encrypt: (peer, pt, boundary) => withProviderEffect(boundary, async () => nip44Encrypt(pt, getConversationKey(this.privkey, peer))),
            decrypt: (peer, ct, boundary) => withProviderEffect(boundary, async () => nip44Decrypt(ct, getConversationKey(this.privkey, peer))),
        };
    }
    async signEvent(template, boundary) {
        const filled = {
            kind: template.kind,
            content: template.content,
            created_at: template.created_at ?? Math.floor(Date.now() / 1000),
            tags: (template.tags ?? []).map(tag => [...tag]),
        };
        if (boundary === undefined)
            return finalizeEvent(filled, this.privkey);
        return withProviderEffect(boundary, async () => finalizeEvent(filled, this.privkey));
    }
    async close() {
        // Best-effort wipe — the engine may already have copies in CoW pages, but
        // zeroing here at least gives a consistent shape with bunker.close().
        this.privkey.fill(0);
    }
}
/** True when the pasted text is a NIP-49 password-encrypted key (`ncryptsec1...`). */
export function isEncryptedNsec(input) {
    return input.trim().toLowerCase().startsWith('ncryptsec1');
}
/**
 * Decode a bech32 nsec into a LocalSigner. Accepts the `nsec1...` prefix, a
 * raw 64-char hex private key for power-user paste paths, or a NIP-49
 * `ncryptsec1...` together with the password that encrypted it.
 * Throws on any malformed input — caller surfaces the error to the user.
 */
export function createLocalSignerFromNsec(input, password) {
    const trimmed = input.trim();
    if (!trimmed)
        throw new Error('empty-nsec');
    let sk;
    if (isEncryptedNsec(trimmed)) {
        if (!password)
            throw new Error('password-required');
        try {
            sk = nip49Decrypt(trimmed, password);
        }
        catch {
            // nostr-tools reports a bad password as an AEAD failure; a malformed
            // ncryptsec as a bech32 error. Neither detail helps the person pasting.
            throw new Error('wrong-password-or-invalid-ncryptsec');
        }
    }
    else if (trimmed.startsWith('nsec1')) {
        const decoded = nip19Decode(trimmed);
        if (decoded.type !== 'nsec')
            throw new Error('not-an-nsec');
        sk = decoded.data;
    }
    else if (/^[0-9a-f]{64}$/i.test(trimmed)) {
        sk = new Uint8Array(32);
        for (let i = 0; i < 32; i++)
            sk[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    else {
        throw new Error('invalid-nsec-format');
    }
    if (sk.length !== 32)
        throw new Error('invalid-nsec-length');
    const pubkey = getPublicKey(sk);
    if (!/^[0-9a-f]{64}$/i.test(pubkey))
        throw new Error('invalid-pubkey-from-nsec');
    return new LocalSigner(pubkey.toLowerCase(), sk);
}
// ── Ephemeral (redirect-only) ─────────────────────────────────────────────────
/**
 * Auth-only signer returned by the redirect/QR flow before Option B is built.
 * Holds the signed challenge but cannot sign further events.
 */
export class EphemeralSigner {
    constructor(pubkey, authEvent) {
        this.pubkey = pubkey;
        this.authEvent = authEvent;
        this.method = 'redirect';
        this.capabilities = { canSignEvents: false, hasNip44: false };
    }
    async signEvent(_template) {
        throw new Error('signer-auth-only: this session was established via redirect and cannot sign new events. ' +
            'Install a NIP-07 extension (bark, Alby) or paste a bunker URI to upgrade.');
    }
    async close() {
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
export class DeferredBunkerSigner {
    constructor(pubkey, authEvent, 
    /** Resolves to the connected bunker, or null if the connect failed. */
    upgrade, 
    /** Original bunker URI — exposed so persistence can reconnect on reload. */
    bunkerUri, 
    /** Stable client key — exposed so persistence keeps the same NIP-46 client pubkey. */
    clientSecretKey, optimisticCapabilities = true) {
        this.pubkey = pubkey;
        this.authEvent = authEvent;
        this.upgrade = upgrade;
        this.bunkerUri = bunkerUri;
        this.clientSecretKey = clientSecretKey;
        this.providerEffectBoundary = 1;
        this.method = 'bunker';
        _DeferredBunkerSigner_binding.set(this, void 0);
        _DeferredBunkerSigner_refusal.set(this, void 0);
        _DeferredBunkerSigner_closed.set(this, false);
        if (clientSecretKey !== undefined && (!(clientSecretKey instanceof Uint8Array) || clientSecretKey.length !== 32)) {
            throw new Error('invalid-client-secret-key');
        }
        __classPrivateFieldSet(this, _DeferredBunkerSigner_binding, { pubkey, uri: bunkerUri?.trim(), source: clientSecretKey,
            key: clientSecretKey && Uint8Array.prototype.slice.call(clientSecretKey) }, "f");
        this.capabilities = {
            canSignEvents: optimisticCapabilities,
            hasNip44: optimisticCapabilities,
        };
        void this.upgrade.then(signer => {
            if (signer && !__classPrivateFieldGet(this, _DeferredBunkerSigner_closed, "f") && !__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f") && this.matchesBinding(signer)) {
                this.capabilities.canSignEvents = true;
                this.capabilities.hasNip44 = true;
            }
        }).catch(() => { });
        this.nip04 = {
            encrypt: async (peer, pt, boundary) => { const signer = await this.live(boundary); return this.invokeBound(signer, boundary, guarded => signer.nip04.encrypt(peer, pt, guarded)); },
            decrypt: async (peer, ct, boundary) => { const signer = await this.live(boundary); return this.invokeBound(signer, boundary, guarded => signer.nip04.decrypt(peer, ct, guarded)); },
        };
        this.nip44 = {
            encrypt: async (peer, pt, boundary) => { const signer = await this.live(boundary); return this.invokeBound(signer, boundary, guarded => signer.nip44.encrypt(peer, pt, guarded)); },
            decrypt: async (peer, ct, boundary) => { const signer = await this.live(boundary); return this.invokeBound(signer, boundary, guarded => signer.nip44.decrypt(peer, ct, guarded)); },
        };
        this.nip46 = {
            ping: async () => (await this.live()).nip46.ping(),
            switchRelays: async () => (await this.live()).nip46.switchRelays(),
            logout: async () => (await this.live()).nip46.logout(),
            provisionRendezvous: async (index, nonce, expiresAt) => (await this.live()).nip46.provisionRendezvous(index, nonce, expiresAt),
        };
    }
    matchesBinding(signer) {
        try {
            const { pubkey, uri, key, source } = __classPrivateFieldGet(this, _DeferredBunkerSigner_binding, "f");
            return this.pubkey === pubkey && signer.pubkey === pubkey && this.bunkerUri?.trim() === uri &&
                (uri === undefined || signer.bunkerUri === uri) && this.clientSecretKey === source &&
                (!key || source?.length === 32 && signer.clientSecretKey?.length === 32 &&
                    key.every((byte, index) => source[index] === byte && signer.clientSecretKey[index] === byte)) && !__classPrivateFieldGet(this, _DeferredBunkerSigner_closed, "f");
        }
        catch {
            return false;
        }
    }
    refuse(signer) {
        if (__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f"))
            return;
        this.capabilities.canSignEvents = false;
        this.capabilities.hasNip44 = false;
        __classPrivateFieldGet(this, _DeferredBunkerSigner_binding, "f").key?.fill(0);
        __classPrivateFieldSet(this, _DeferredBunkerSigner_refusal, Promise.resolve().then(() => signer.close()).catch(() => { }), "f");
    }
    async invokeBound(signer, boundary, invoke) {
        const guarded = boundary && {
            start: (provider) => boundary.start(() => {
                if (__classPrivateFieldGet(this, _DeferredBunkerSigner_closed, "f"))
                    throw new Error('deferred-bunker-closed');
                // Recheck inside the consumer's decision too: its native read may
                // have yielded since live() checked the upgraded signer.
                if (__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f") || !this.matchesBinding(signer)) {
                    this.refuse(signer);
                    throw new Error('deferred-bunker-binding-mismatch');
                }
                return provider();
            }),
        };
        try {
            return await invoke(guarded);
        }
        finally {
            if (__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f"))
                await __classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f");
        }
    }
    async live(boundary) {
        const signer = await this.upgrade;
        if (__classPrivateFieldGet(this, _DeferredBunkerSigner_closed, "f"))
            throw new Error('deferred-bunker-closed');
        if (__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f")) {
            await __classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f");
            throw new Error('deferred-bunker-binding-mismatch');
        }
        if (!signer) {
            throw new Error('signer-auth-only: the redirect bunker handoff did not connect, so this ' +
                'session cannot sign. Reconnect the signer or paste a bunker URI to upgrade.');
        }
        // A substituted upgrade must never receive event data or plaintext, even
        // if its final signature would later be rejected by the consumer.
        if (!this.matchesBinding(signer) || boundary !== undefined && signer.providerEffectBoundary !== 1) {
            this.refuse(signer);
            await __classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f");
            throw new Error('deferred-bunker-binding-mismatch');
        }
        return signer;
    }
    async signEvent(template, boundary) {
        const captured = { ...template, tags: (template.tags ?? []).map(tag => [...tag]) };
        const signer = await this.live(boundary);
        return this.invokeBound(signer, boundary, guarded => signer.signEvent(captured, guarded));
    }
    async close() {
        __classPrivateFieldSet(this, _DeferredBunkerSigner_closed, true, "f");
        const signer = await this.upgrade.catch(() => null);
        if (__classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f"))
            await __classPrivateFieldGet(this, _DeferredBunkerSigner_refusal, "f");
        else if (signer)
            await signer.close().catch(() => { });
        __classPrivateFieldGet(this, _DeferredBunkerSigner_binding, "f").key?.fill(0);
    }
}
_DeferredBunkerSigner_binding = new WeakMap(), _DeferredBunkerSigner_refusal = new WeakMap(), _DeferredBunkerSigner_closed = new WeakMap();
