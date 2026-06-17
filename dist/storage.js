/**
 * localStorage persistence for signet-login sessions.
 *
 * Storage keys are namespaced under `signet:login.*` so they don't collide
 * with `signet:verify.*` or any future Signet SDK.
 */
import { STORAGE_KEYS } from './types.js';
function safeGet(key) {
    try {
        return typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null;
    }
    catch {
        return null;
    }
}
function safeSet(key, value) {
    try {
        if (typeof localStorage !== 'undefined')
            localStorage.setItem(key, value);
    }
    catch {
        // localStorage unavailable (private mode, quota, etc.) — silently skip
    }
}
function safeRemove(key) {
    try {
        if (typeof localStorage !== 'undefined')
            localStorage.removeItem(key);
    }
    catch {
        // ignore
    }
}
async function safeGetFrom(storage, key) {
    if (!storage)
        return safeGet(key);
    try {
        return await storage.getItem(key);
    }
    catch {
        return null;
    }
}
async function safeSetTo(storage, key, value) {
    if (!storage) {
        safeSet(key, value);
        return;
    }
    try {
        await storage.setItem(key, value);
    }
    catch {
        // Custom storage may be unavailable/quota-limited. Match localStorage's
        // best-effort behaviour and avoid failing the login itself.
    }
}
async function safeRemoveFrom(storage, key) {
    if (!storage) {
        safeRemove(key);
        return;
    }
    try {
        await storage.removeItem(key);
    }
    catch {
        // ignore
    }
}
/** Save a session. Caller must serialise authEvent to JSON. */
export function saveSession(s) {
    safeSet(STORAGE_KEYS.pubkey, s.pubkey);
    safeSet(STORAGE_KEYS.method, s.method);
    safeSet(STORAGE_KEYS.authEvent, s.authEventJson);
    if (s.bunkerUri !== undefined)
        safeSet(STORAGE_KEYS.bunkerUri, s.bunkerUri);
    else
        safeRemove(STORAGE_KEYS.bunkerUri);
    if (s.bunkerClientSkHex !== undefined)
        safeSet(STORAGE_KEYS.bunkerClientSk, s.bunkerClientSkHex);
    else
        safeRemove(STORAGE_KEYS.bunkerClientSk);
    if (s.expiresAt !== undefined)
        safeSet(STORAGE_KEYS.expiresAt, String(s.expiresAt));
    else
        safeRemove(STORAGE_KEYS.expiresAt);
    if (s.displayName !== undefined)
        safeSet(STORAGE_KEYS.displayName, s.displayName);
    else
        safeRemove(STORAGE_KEYS.displayName);
}
/** Async-storage variant of `saveSession`. */
export async function saveSessionToStorage(s, storage) {
    await safeSetTo(storage, STORAGE_KEYS.pubkey, s.pubkey);
    await safeSetTo(storage, STORAGE_KEYS.method, s.method);
    await safeSetTo(storage, STORAGE_KEYS.authEvent, s.authEventJson);
    if (s.bunkerUri !== undefined)
        await safeSetTo(storage, STORAGE_KEYS.bunkerUri, s.bunkerUri);
    else
        await safeRemoveFrom(storage, STORAGE_KEYS.bunkerUri);
    if (s.bunkerClientSkHex !== undefined)
        await safeSetTo(storage, STORAGE_KEYS.bunkerClientSk, s.bunkerClientSkHex);
    else
        await safeRemoveFrom(storage, STORAGE_KEYS.bunkerClientSk);
    if (s.expiresAt !== undefined)
        await safeSetTo(storage, STORAGE_KEYS.expiresAt, String(s.expiresAt));
    else
        await safeRemoveFrom(storage, STORAGE_KEYS.expiresAt);
    if (s.displayName !== undefined)
        await safeSetTo(storage, STORAGE_KEYS.displayName, s.displayName);
    else
        await safeRemoveFrom(storage, STORAGE_KEYS.displayName);
}
function shapeSession(values) {
    const { pubkey, authEventJson } = values;
    const method = values.method;
    if (!pubkey || !method || !authEventJson)
        return null;
    if (!/^[0-9a-f]{64}$/i.test(pubkey))
        return null;
    if (method !== 'nip07' && method !== 'redirect' && method !== 'bunker' && method !== 'amber')
        return null;
    let authEvent;
    try {
        authEvent = JSON.parse(authEventJson);
        if (typeof authEvent !== 'object' || authEvent === null)
            return null;
        if (authEvent.pubkey !== pubkey)
            return null;
    }
    catch {
        return null;
    }
    const expiresAt = values.expiresAtRaw ? Number(values.expiresAtRaw) : undefined;
    if (expiresAt !== undefined && !Number.isFinite(expiresAt))
        return null;
    const result = { pubkey, method, authEventJson };
    if (values.bunkerUri)
        result.bunkerUri = values.bunkerUri;
    if (values.bunkerClientSkHex)
        result.bunkerClientSkHex = values.bunkerClientSkHex;
    if (expiresAt !== undefined)
        result.expiresAt = expiresAt;
    if (values.displayName)
        result.displayName = values.displayName;
    return result;
}
/** Load a session if one is present. Returns null if no session or it's malformed. */
export function loadSession() {
    const result = shapeSession({
        pubkey: safeGet(STORAGE_KEYS.pubkey),
        method: safeGet(STORAGE_KEYS.method),
        authEventJson: safeGet(STORAGE_KEYS.authEvent),
        bunkerUri: safeGet(STORAGE_KEYS.bunkerUri),
        bunkerClientSkHex: safeGet(STORAGE_KEYS.bunkerClientSk),
        expiresAtRaw: safeGet(STORAGE_KEYS.expiresAt),
        displayName: safeGet(STORAGE_KEYS.displayName),
    });
    if (!result)
        return null;
    if (result.expiresAt !== undefined && Date.now() > result.expiresAt) {
        clearSession();
        return null;
    }
    return result;
}
/** Async-storage variant of `loadSession`. */
export async function loadSessionFromStorage(storage) {
    const result = shapeSession({
        pubkey: await safeGetFrom(storage, STORAGE_KEYS.pubkey),
        method: await safeGetFrom(storage, STORAGE_KEYS.method),
        authEventJson: await safeGetFrom(storage, STORAGE_KEYS.authEvent),
        bunkerUri: await safeGetFrom(storage, STORAGE_KEYS.bunkerUri),
        bunkerClientSkHex: await safeGetFrom(storage, STORAGE_KEYS.bunkerClientSk),
        expiresAtRaw: await safeGetFrom(storage, STORAGE_KEYS.expiresAt),
        displayName: await safeGetFrom(storage, STORAGE_KEYS.displayName),
    });
    if (!result)
        return null;
    if (result.expiresAt !== undefined && Date.now() > result.expiresAt) {
        await clearSessionFromStorage(storage);
        return null;
    }
    return result;
}
/** Clear all signet-login keys. Does not touch other Signet SDK storage.
 *
 * Note: `clientSk` (the persistent NIP-46 client identity, see
 * `loadOrCreatePersistentClientSk`) is deliberately NOT cleared. It is the
 * browser's stable transport identity to bunkers, not session state — keeping
 * it means a re-login presents the same client pubkey and stays auto-approved
 * by the signer. Use `clearPersistentClientSk` for an explicit reset. */
export function clearSession() {
    safeRemove(STORAGE_KEYS.pubkey);
    safeRemove(STORAGE_KEYS.method);
    safeRemove(STORAGE_KEYS.authEvent);
    safeRemove(STORAGE_KEYS.bunkerUri);
    safeRemove(STORAGE_KEYS.bunkerClientSk);
    safeRemove(STORAGE_KEYS.expiresAt);
    safeRemove(STORAGE_KEYS.displayName);
}
/** Async-storage variant of `clearSession`. */
export async function clearSessionFromStorage(storage) {
    await safeRemoveFrom(storage, STORAGE_KEYS.pubkey);
    await safeRemoveFrom(storage, STORAGE_KEYS.method);
    await safeRemoveFrom(storage, STORAGE_KEYS.authEvent);
    await safeRemoveFrom(storage, STORAGE_KEYS.bunkerUri);
    await safeRemoveFrom(storage, STORAGE_KEYS.bunkerClientSk);
    await safeRemoveFrom(storage, STORAGE_KEYS.expiresAt);
    await safeRemoveFrom(storage, STORAGE_KEYS.displayName);
}
/**
 * Load the persistent NIP-46 client secret key for this browser/origin,
 * generating and storing one on first use. Reused across every bunker connect
 * (paste, redirect upgrade, QR upgrade, nostrconnect, restore) so the client
 * pubkey is stable. A bunker that auto-approves a bound client pubkey per slot
 * (e.g. Heartwood) then keeps auto-approving instead of prompting per request.
 *
 * Survives logout. If localStorage is unavailable (private mode, quota) a fresh
 * ephemeral key is returned each call — degrades to the old behaviour rather
 * than throwing.
 */
export function loadOrCreatePersistentClientSk() {
    const existing = safeGet(STORAGE_KEYS.clientSk);
    if (existing && /^[0-9a-f]{64}$/i.test(existing)) {
        try {
            return hexToBytesLocal(existing);
        }
        catch {
            // Corrupt value — fall through and regenerate.
        }
    }
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    safeSet(STORAGE_KEYS.clientSk, bytesToHexLocal(sk));
    return sk;
}
/** Async-storage variant of `loadOrCreatePersistentClientSk`. */
export async function loadOrCreatePersistentClientSkFromStorage(storage) {
    const existing = await safeGetFrom(storage, STORAGE_KEYS.clientSk);
    if (existing && /^[0-9a-f]{64}$/i.test(existing)) {
        try {
            return hexToBytesLocal(existing);
        }
        catch {
            // Corrupt value — fall through and regenerate.
        }
    }
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    await safeSetTo(storage, STORAGE_KEYS.clientSk, bytesToHexLocal(sk));
    return sk;
}
/** Forget the persistent client key, forcing a fresh one on next connect. */
export function clearPersistentClientSk() {
    safeRemove(STORAGE_KEYS.clientSk);
}
/** Async-storage variant of `clearPersistentClientSk`. */
export async function clearPersistentClientSkFromStorage(storage) {
    await safeRemoveFrom(storage, STORAGE_KEYS.clientSk);
}
// ── Pending-redirect persistence ──────────────────────────────────────────────
/**
 * Persist the in-flight redirect state. Called immediately before navigating
 * to signet-app so the callback consumer can validate the round-trip.
 *
 * Stored as a single JSON blob under `signet:login.pendingRedirect`. We keep
 * it in localStorage rather than sessionStorage because some browsers (older
 * iOS Safari especially) wipe sessionStorage on cross-origin navigation.
 */
export function savePendingRedirect(p) {
    safeSet(STORAGE_KEYS.pendingRedirect, JSON.stringify(p));
}
/** Async-storage variant of `savePendingRedirect`. */
export async function savePendingRedirectToStorage(p, storage) {
    await safeSetTo(storage, STORAGE_KEYS.pendingRedirect, JSON.stringify(p));
}
function shapePendingRedirect(raw) {
    if (!raw)
        return null;
    try {
        const parsed = JSON.parse(raw);
        const challenge = parsed.challenge;
        const origin = parsed.origin;
        const appName = parsed.appName;
        const createdAt = parsed.createdAt;
        if (typeof challenge !== 'string' || !/^[0-9a-f]{64}$/i.test(challenge))
            return null;
        if (typeof origin !== 'string' || origin.length === 0)
            return null;
        if (typeof appName !== 'string' || appName.length === 0)
            return null;
        if (typeof createdAt !== 'number' || !Number.isFinite(createdAt))
            return null;
        return { challenge, origin, appName, createdAt };
    }
    catch {
        return null;
    }
}
/** Load and shape-validate the pending redirect. Returns null if absent or malformed. */
export function loadPendingRedirect() {
    return shapePendingRedirect(safeGet(STORAGE_KEYS.pendingRedirect));
}
/** Async-storage variant of `loadPendingRedirect`. */
export async function loadPendingRedirectFromStorage(storage) {
    return shapePendingRedirect(await safeGetFrom(storage, STORAGE_KEYS.pendingRedirect));
}
/** Clear the pending-redirect record. Safe to call when none exists. */
export function clearPendingRedirect() {
    safeRemove(STORAGE_KEYS.pendingRedirect);
}
/** Async-storage variant of `clearPendingRedirect`. */
export async function clearPendingRedirectFromStorage(storage) {
    await safeRemoveFrom(storage, STORAGE_KEYS.pendingRedirect);
}
// ── Hex helpers (avoid pulling in @noble for two functions) ───────────────────
export function bytesToHexLocal(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
}
export function hexToBytesLocal(hex) {
    if (hex.length % 2 !== 0)
        throw new Error('odd-hex-length');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
