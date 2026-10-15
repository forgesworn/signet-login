/**
 * localStorage persistence for signet-login sessions.
 *
 * Storage keys are namespaced under `signet:login.*` so they don't collide
 * with `signet:verify.*` or any future Signet SDK.
 */

import { AUTH_FRESHNESS_WINDOW_SEC } from 'signet-verify';
import { schnorr } from '@noble/curves/secp256k1';
import { verifyLogin } from './verify.js';

import type { LoginMethod, PendingRedirect, PendingRelayAuth, SignetAuthEvent, SignetStorage } from './types.js';
import { STORAGE_KEYS } from './types.js';

/** Raw shape of a persisted session — flat string fields, JSON for the auth event. */
export interface PersistedSession {
  pubkey: string;
  method: LoginMethod;
  authEventJson: string;
  bunkerUri?: string;
  bunkerClientSkHex?: string;
  expiresAt?: number;
  displayName?: string;
}

function safeGet(key: string): string | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null;
  } catch {
    return null;
  }
}

function safeSet(key: string, value: string): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(key, value);
  } catch {
    // localStorage unavailable (private mode, quota, etc.) — silently skip
  }
}

function safeRemove(key: string): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.removeItem(key);
  } catch {
    // ignore
  }
}

async function safeGetFrom(storage: SignetStorage | undefined, key: string): Promise<string | null> {
  if (!storage) return safeGet(key);
  const required = storage.required === true;
  try {
    const value = await storage.getItem(key);
    if (required && value !== null && typeof value !== 'string') throw new Error('required-storage-invalid-read');
    return value;
  } catch (error) {
    if (required) throw error;
    return null;
  }
}

async function safeSetTo(storage: SignetStorage | undefined, key: string, value: string): Promise<void> {
  if (!storage) {
    safeSet(key, value);
    return;
  }
  const required = storage.required === true;
  try {
    await storage.setItem(key, value);
  } catch (error) {
    if (required) throw error;
    // Custom storage may be unavailable/quota-limited. Match localStorage's
    // best-effort behaviour and avoid failing the login itself.
  }
}

async function safeRemoveFrom(storage: SignetStorage | undefined, key: string): Promise<void> {
  if (!storage) {
    safeRemove(key);
    return;
  }
  const required = storage.required === true;
  try {
    await storage.removeItem(key);
  } catch (error) {
    if (required) throw error;
    // ignore
  }
}

/** Check the required session contract before login can produce effects. */
export function assertRequiredSessionStorage(storage?: SignetStorage): void {
  if (storage?.required && (typeof storage.getItems !== 'function' || typeof storage.setItems !== 'function' || typeof storage.compareAndSetItem !== 'function')) {
    throw new Error('required-storage-atomic-session-unavailable');
  }
}

const SESSION_KEYS = Object.freeze([
  STORAGE_KEYS.pubkey, STORAGE_KEYS.method, STORAGE_KEYS.authEvent,
  STORAGE_KEYS.bunkerUri, STORAGE_KEYS.bunkerClientSk,
  STORAGE_KEYS.expiresAt, STORAGE_KEYS.displayName,
]);

async function requiredCas(storage: SignetStorage, key: string, expected: string | null, value: string | null): Promise<boolean> {
  if (!storage.compareAndSetItem) throw new Error('required-storage-atomic-cas-unavailable');
  const committed = await storage.compareAndSetItem(key, expected, value);
  if (typeof committed !== 'boolean') throw new Error('required-storage-invalid-cas-receipt');
  return committed;
}

const pendingReceipts = new WeakMap<object, { storage: SignetStorage; raw: string }>();
async function retainPending(storage: SignetStorage, key: string, record: object, raw: string): Promise<void> {
  if (!await requiredCas(storage, key, null, raw)) throw new Error('required-storage-pending-conflict');
  pendingReceipts.set(record, {storage, raw});
}
async function removePending(storage: SignetStorage, key: string, record: object | null): Promise<void> {
  if (!record) return; // A preceding authenticated read already proved absence.
  const receipt = pendingReceipts.get(record);
  if (!receipt || receipt.storage !== storage) throw new Error('required-storage-pending-receipt-unavailable');
  if (!await requiredCas(storage, key, receipt.raw, null)) {
    // A different request must survive an old request's cancellation. Known
    // absence is idempotent; any replacement is a hold, never a blind delete.
    if (await safeGetFrom(storage, key) !== null) throw new Error('required-storage-pending-conflict');
  }
}

async function requiredSnapshot(storage: SignetStorage): Promise<Readonly<Record<string, string | null>>> {
  if (!storage.getItems) throw new Error('required-storage-atomic-read-unavailable');
  const values = await storage.getItems(SESSION_KEYS);
  if (typeof values !== 'object' || values === null || Object.keys(values).length !== SESSION_KEYS.length ||
      SESSION_KEYS.some(key => !Object.prototype.hasOwnProperty.call(values, key) ||
        (values[key] !== null && typeof values[key] !== 'string'))) {
    throw new Error('required-storage-invalid-snapshot');
  }
  return Object.freeze(Object.fromEntries(SESSION_KEYS.map(key => [key, values[key]])));
}

async function requiredReplacement(storage: SignetStorage, changes: Record<string, string | null>, expected?: Readonly<Record<string, string | null>>): Promise<void> {
  if (!storage.setItems) throw new Error('required-storage-atomic-write-unavailable');
  const snapshot = expected ?? await requiredSnapshot(storage);
  const committed = await storage.setItems(Object.freeze(changes), snapshot);
  if (committed !== true) throw new Error(committed === false ? 'required-storage-session-conflict' : 'required-storage-invalid-batch-receipt');
}

function validSecret(hex: string | null | undefined): boolean {
  if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) return false;
  const bytes = hexToBytesLocal(hex);
  try { schnorr.getPublicKey(bytes); return true; }
  catch { return false; }
  finally { bytes.fill(0); }
}

function validRequiredSession(values: LoadedSessionValues): boolean {
  const session = shapeSession(values);
  if (!session) return false;
  try {
    const event = JSON.parse(session.authEventJson) as SignetAuthEvent;
    if (!Number.isSafeInteger(event.created_at) || event.created_at < 0 ||
        !Array.isArray(event.tags) || !event.tags.every(tag => Array.isArray(tag) && tag.every(value => typeof value === 'string'))) return false;
    const challenge = event.tags.find(tag => tag[0] === 'challenge')?.[1];
    const origin = event.tags.find(tag => tag[0] === 'origin')?.[1];
    // Verify the stored proof's integrity, not a fresh server login. The
    // backend supplies account/origin binding and anti-rollback authority.
    if (!challenge || !origin || !verifyLogin(event, { expectedChallenge: challenge,
      expectedOrigin: origin, now: () => event.created_at * 1000 }).valid) return false;
    if (values.expiresAtRaw !== null && (values.expiresAtRaw.trim() === '' ||
        !Number.isSafeInteger(session.expiresAt) || session.expiresAt! < 0)) return false;
    if (session.method !== 'bunker') return values.bunkerUri === null && values.bunkerClientSkHex === null;
    if (!validSecret(values.bunkerClientSkHex) || !values.bunkerUri) return false;
    return validBunkerUri(values.bunkerUri);
  } catch { return false; }
}

/**
 * Replace the stored bunker URI with `next`, only while the stored value is
 * still `expected` (another tab or login may have replaced the session since).
 * Used when a restored signer's `switch_relays` reply moved it to new relays.
 * Every other session key is left untouched.
 */
export async function replaceStoredBunkerUri(expected: string, next: string, storage?: SignetStorage): Promise<void> {
  if (expected === next || !validBunkerUri(next)) return;
  if (storage?.required) {
    const snapshot = await requiredSnapshot(storage);
    if (snapshot[STORAGE_KEYS.bunkerUri] !== expected) return;
    const values: LoadedSessionValues = {
      pubkey: snapshot[STORAGE_KEYS.pubkey], method: snapshot[STORAGE_KEYS.method],
      authEventJson: snapshot[STORAGE_KEYS.authEvent], bunkerUri: next,
      bunkerClientSkHex: snapshot[STORAGE_KEYS.bunkerClientSk], expiresAtRaw: snapshot[STORAGE_KEYS.expiresAt],
      displayName: snapshot[STORAGE_KEYS.displayName],
    };
    if (!validRequiredSession(values)) return;
    await requiredReplacement(storage, { [STORAGE_KEYS.bunkerUri]: next }, snapshot);
    return;
  }
  if (await safeGetFrom(storage, STORAGE_KEYS.bunkerUri) !== expected) return;
  await safeSetTo(storage, STORAGE_KEYS.bunkerUri, next);
}

function validBunkerUri(value: string): boolean {
  try {
    const uri = new URL(value);
    return uri.protocol === 'bunker:' && /^[0-9a-f]{64}$/i.test(uri.hostname) &&
      uri.pathname === '' && uri.hash === '' && uri.username === '' && uri.password === '' &&
      uri.searchParams.getAll('relay').length > 0 && uri.searchParams.getAll('relay').every(relay => {
        const url = new URL(relay); return url.protocol === 'wss:' || url.protocol === 'ws:';
      });
  } catch { return false; }
}

/** Save a session. Caller must serialise authEvent to JSON. */
export function saveSession(s: PersistedSession): void {
  safeSet(STORAGE_KEYS.pubkey, s.pubkey);
  safeSet(STORAGE_KEYS.method, s.method);
  safeSet(STORAGE_KEYS.authEvent, s.authEventJson);
  if (s.bunkerUri !== undefined) safeSet(STORAGE_KEYS.bunkerUri, s.bunkerUri);
  else safeRemove(STORAGE_KEYS.bunkerUri);
  if (s.bunkerClientSkHex !== undefined) safeSet(STORAGE_KEYS.bunkerClientSk, s.bunkerClientSkHex);
  else safeRemove(STORAGE_KEYS.bunkerClientSk);
  if (s.expiresAt !== undefined) safeSet(STORAGE_KEYS.expiresAt, String(s.expiresAt));
  else safeRemove(STORAGE_KEYS.expiresAt);
  if (s.displayName !== undefined) safeSet(STORAGE_KEYS.displayName, s.displayName);
  else safeRemove(STORAGE_KEYS.displayName);
}

/** Async-storage variant of `saveSession`. */
export async function saveSessionToStorage(s: PersistedSession, storage?: SignetStorage): Promise<void> {
  if (storage?.required) {
    const values: LoadedSessionValues = { pubkey: s.pubkey, method: s.method, authEventJson: s.authEventJson,
      bunkerUri: s.bunkerUri ?? null, bunkerClientSkHex: s.bunkerClientSkHex ?? null,
      expiresAtRaw: s.expiresAt === undefined ? null : String(s.expiresAt), displayName: s.displayName ?? null };
    if (!validRequiredSession(values)) throw new Error('required-storage-invalid-session');
    await requiredReplacement(storage, {
      [STORAGE_KEYS.pubkey]: values.pubkey, [STORAGE_KEYS.method]: values.method,
      [STORAGE_KEYS.authEvent]: values.authEventJson, [STORAGE_KEYS.bunkerUri]: values.bunkerUri,
      [STORAGE_KEYS.bunkerClientSk]: values.bunkerClientSkHex, [STORAGE_KEYS.expiresAt]: values.expiresAtRaw,
      [STORAGE_KEYS.displayName]: values.displayName,
    });
    return;
  }
  await safeSetTo(storage, STORAGE_KEYS.pubkey, s.pubkey);
  await safeSetTo(storage, STORAGE_KEYS.method, s.method);
  await safeSetTo(storage, STORAGE_KEYS.authEvent, s.authEventJson);
  if (s.bunkerUri !== undefined) await safeSetTo(storage, STORAGE_KEYS.bunkerUri, s.bunkerUri);
  else await safeRemoveFrom(storage, STORAGE_KEYS.bunkerUri);
  if (s.bunkerClientSkHex !== undefined) await safeSetTo(storage, STORAGE_KEYS.bunkerClientSk, s.bunkerClientSkHex);
  else await safeRemoveFrom(storage, STORAGE_KEYS.bunkerClientSk);
  if (s.expiresAt !== undefined) await safeSetTo(storage, STORAGE_KEYS.expiresAt, String(s.expiresAt));
  else await safeRemoveFrom(storage, STORAGE_KEYS.expiresAt);
  if (s.displayName !== undefined) await safeSetTo(storage, STORAGE_KEYS.displayName, s.displayName);
  else await safeRemoveFrom(storage, STORAGE_KEYS.displayName);
}

interface LoadedSessionValues {
  pubkey: string | null;
  method: string | null;
  authEventJson: string | null;
  bunkerUri: string | null;
  bunkerClientSkHex: string | null;
  expiresAtRaw: string | null;
  displayName: string | null;
}

function shapeSession(values: LoadedSessionValues): PersistedSession | null {
  const { pubkey, authEventJson } = values;
  const method = values.method as LoginMethod | null;
  if (!pubkey || !method || !authEventJson) return null;
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) return null;
  if (method !== 'nip07' && method !== 'redirect' && method !== 'bunker' && method !== 'amber') return null;

  let authEvent: SignetAuthEvent;
  try {
    authEvent = JSON.parse(authEventJson);
    if (typeof authEvent !== 'object' || authEvent === null) return null;
    if (authEvent.pubkey !== pubkey) return null;
  } catch {
    return null;
  }

  const expiresAt = values.expiresAtRaw ? Number(values.expiresAtRaw) : undefined;
  if (expiresAt !== undefined && !Number.isFinite(expiresAt)) return null;

  const result: PersistedSession = { pubkey, method, authEventJson };
  if (values.bunkerUri) result.bunkerUri = values.bunkerUri;
  if (values.bunkerClientSkHex) result.bunkerClientSkHex = values.bunkerClientSkHex;
  if (expiresAt !== undefined) result.expiresAt = expiresAt;
  if (values.displayName) result.displayName = values.displayName;
  return result;
}

/** Load a session if one is present. Returns null if no session or it's malformed. */
export function loadSession(): PersistedSession | null {
  const result = shapeSession({
    pubkey: safeGet(STORAGE_KEYS.pubkey),
    method: safeGet(STORAGE_KEYS.method),
    authEventJson: safeGet(STORAGE_KEYS.authEvent),
    bunkerUri: safeGet(STORAGE_KEYS.bunkerUri),
    bunkerClientSkHex: safeGet(STORAGE_KEYS.bunkerClientSk),
    expiresAtRaw: safeGet(STORAGE_KEYS.expiresAt),
    displayName: safeGet(STORAGE_KEYS.displayName),
  });
  if (!result) return null;
  if (result.expiresAt !== undefined && Date.now() > result.expiresAt) {
    clearSession();
    return null;
  }
  return result;
}

/** Async-storage variant of `loadSession`. */
export async function loadSessionFromStorage(storage?: SignetStorage): Promise<PersistedSession | null> {
  const required = storage?.required === true;
  const snapshot = required ? await requiredSnapshot(storage!) : null;
  const read = (key: string): Promise<string | null> => snapshot ? Promise.resolve(snapshot[key]) : safeGetFrom(storage, key);
  const values: LoadedSessionValues = {
    pubkey: await read(STORAGE_KEYS.pubkey),
    method: await read(STORAGE_KEYS.method),
    authEventJson: await read(STORAGE_KEYS.authEvent),
    bunkerUri: await read(STORAGE_KEYS.bunkerUri),
    bunkerClientSkHex: await read(STORAGE_KEYS.bunkerClientSk),
    expiresAtRaw: await read(STORAGE_KEYS.expiresAt),
    displayName: await read(STORAGE_KEYS.displayName),
  };
  const result = shapeSession(values);
  if (required && Object.values(values).some(value => value !== null) && !validRequiredSession(values)) {
    throw new Error('required-storage-invalid-session');
  }
  if (!result) {
    if (required && Object.values(values).some(value => value !== null)) throw new Error('required-storage-invalid-session');
    return null;
  }
  if (result.expiresAt !== undefined && Date.now() > result.expiresAt) {
    await clearSessionFromStorage(storage, snapshot ?? undefined);
    return null;
  }
  return result;
}

/** Clear all signet-login keys. Does not touch other Signet SDK storage.
 *
 * Note: `clientSk` (the persistent NIP-46 client identity, see
 * `loadOrCreatePersistentClientSk`) is deliberately NOT cleared. It is the
 * browser's stable transport identity used for NEW logins/pairings, not
 * session state — keeping it means a fresh login presents the same client
 * pubkey and stays auto-approved by the signer. Restoring an existing session
 * uses the session's own `bunkerClientSk` and never touches `clientSk`.
 * Use `clearPersistentClientSk` for an explicit reset. */
export function clearSession(): void {
  safeRemove(STORAGE_KEYS.pubkey);
  safeRemove(STORAGE_KEYS.method);
  safeRemove(STORAGE_KEYS.authEvent);
  safeRemove(STORAGE_KEYS.bunkerUri);
  safeRemove(STORAGE_KEYS.bunkerClientSk);
  safeRemove(STORAGE_KEYS.expiresAt);
  safeRemove(STORAGE_KEYS.displayName);
  // A logged-out user should not leave a resumable sign-in (and its session
  // private key) sitting in storage behind them.
  safeRemove(STORAGE_KEYS.pendingRelayAuth);
}

/** Async-storage variant of `clearSession`. */
export async function clearSessionFromStorage(storage?: SignetStorage, expected?: Readonly<Record<string, string | null>>): Promise<void> {
  if (storage?.required) {
    const snapshot = expected ?? await requiredSnapshot(storage);
    const relay = await loadPendingRelayAuth(storage);
    const redirect = await loadPendingRedirectFromStorage(storage);
    await requiredReplacement(storage, Object.fromEntries(SESSION_KEYS.map(key => [key, null])), snapshot);
    await clearPendingRelayAuth(storage, relay);
    await clearPendingRedirectFromStorage(storage, redirect);
    return;
  }
  await safeRemoveFrom(storage, STORAGE_KEYS.pubkey);
  await safeRemoveFrom(storage, STORAGE_KEYS.method);
  await safeRemoveFrom(storage, STORAGE_KEYS.authEvent);
  await safeRemoveFrom(storage, STORAGE_KEYS.bunkerUri);
  await safeRemoveFrom(storage, STORAGE_KEYS.bunkerClientSk);
  await safeRemoveFrom(storage, STORAGE_KEYS.expiresAt);
  await safeRemoveFrom(storage, STORAGE_KEYS.displayName);
  // See clearSession() above — a logout must not leave a resumable sign-in's
  // session private key behind.
  await safeRemoveFrom(storage, STORAGE_KEYS.pendingRelayAuth);
}

/**
 * Load the persistent NIP-46 client secret key for this browser/origin,
 * generating and storing one on first use. Used for NEW logins/pairings
 * (paste, redirect upgrade, QR upgrade, nostrconnect) so the client pubkey
 * is stable across fresh connections. A bunker that auto-approves a bound
 * client pubkey per slot (e.g. Heartwood) then keeps auto-approving instead
 * of prompting per request. NOT used by session restore — a stored session
 * reconnects with its own persisted `bunkerClientSk`.
 *
 * Survives logout. If localStorage is unavailable (private mode, quota) a fresh
 * ephemeral key is returned each call — degrades to the old behaviour rather
 * than throwing.
 */
export function loadOrCreatePersistentClientSk(): Uint8Array {
  const existing = safeGet(STORAGE_KEYS.clientSk);
  if (existing && /^[0-9a-f]{64}$/i.test(existing)) {
    try {
      return hexToBytesLocal(existing);
    } catch {
      // Corrupt value — fall through and regenerate.
    }
  }
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  safeSet(STORAGE_KEYS.clientSk, bytesToHexLocal(sk));
  return sk;
}

/** Async-storage variant of `loadOrCreatePersistentClientSk`. */
export async function loadOrCreatePersistentClientSkFromStorage(storage?: SignetStorage): Promise<Uint8Array> {
  const required = storage?.required === true;
  if (required && !storage!.compareAndSetItem) throw new Error('required-storage-atomic-cas-unavailable');
  const existing = await safeGetFrom(storage, STORAGE_KEYS.clientSk);
  if (existing && /^[0-9a-f]{64}$/i.test(existing)) {
    const sk = hexToBytesLocal(existing);
    if (required) {
      try { schnorr.getPublicKey(sk); }
      catch { sk.fill(0); throw new Error('required-storage-invalid-client-key'); }
    }
    return sk;
  }
  if (required && existing !== null) throw new Error('required-storage-invalid-client-key');
  const sk = new Uint8Array(32);
  try {
    crypto.getRandomValues(sk);
    if (required) schnorr.getPublicKey(sk);
    if (required) {
      if (!await requiredCas(storage!, STORAGE_KEYS.clientSk, null, bytesToHexLocal(sk))) {
        sk.fill(0);
        const retained = await safeGetFrom(storage, STORAGE_KEYS.clientSk);
        if (!validSecret(retained)) throw new Error('required-storage-client-key-conflict');
        return hexToBytesLocal(retained!);
      }
    } else await safeSetTo(storage, STORAGE_KEYS.clientSk, bytesToHexLocal(sk));
    return sk;
  } catch (error) {
    // A provisional private key must not escape a failed required receipt.
    sk.fill(0);
    throw error;
  }
}

/** Forget the persistent client key, forcing a fresh one on next connect. */
export function clearPersistentClientSk(): void {
  safeRemove(STORAGE_KEYS.clientSk);
}

/** Async-storage variant of `clearPersistentClientSk`. */
export async function clearPersistentClientSkFromStorage(storage?: SignetStorage): Promise<void> {
  if (storage?.required) {
    const expected = await safeGetFrom(storage, STORAGE_KEYS.clientSk);
    if (expected === null) return;
    if (!validSecret(expected)) throw new Error('required-storage-invalid-client-key');
    if (!await requiredCas(storage, STORAGE_KEYS.clientSk, expected, null) &&
        await safeGetFrom(storage, STORAGE_KEYS.clientSk) !== null) throw new Error('required-storage-client-key-conflict');
  } else await safeRemoveFrom(storage, STORAGE_KEYS.clientSk);
}

/**
 * Strictly decode a 64-hex client secret key. Returns null for missing,
 * malformed hex values. Never falls back to a different key.
 */
export function decodeClientSecretKey(
  hex: string | null | undefined,
): Uint8Array | null {
  if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) return null;
  try {
    return hexToBytesLocal(hex);
  } catch {
    return null;
  }
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
export function savePendingRedirect(p: PendingRedirect): void {
  safeSet(STORAGE_KEYS.pendingRedirect, JSON.stringify(p));
}

/** Async-storage variant of `savePendingRedirect`. */
export async function savePendingRedirectToStorage(p: PendingRedirect, storage?: SignetStorage): Promise<void> {
  if (storage?.required) {
    if (!shapePendingRedirect(JSON.stringify(p))) throw new Error('required-storage-invalid-pending-redirect');
    const existing = await loadPendingRedirectFromStorage(storage);
    if (existing) throw new Error('required-storage-pending-conflict');
    await retainPending(storage, STORAGE_KEYS.pendingRedirect, p, JSON.stringify(p));
  } else await safeSetTo(storage, STORAGE_KEYS.pendingRedirect, JSON.stringify(p));
}

function shapePendingRedirect(raw: string | null): PendingRedirect | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const challenge = parsed.challenge;
    const origin = parsed.origin;
    const appName = parsed.appName;
    const createdAt = parsed.createdAt;
    if (typeof challenge !== 'string' || !/^[0-9a-f]{64}$/i.test(challenge)) return null;
    if (typeof origin !== 'string' || origin.length === 0) return null;
    if (typeof appName !== 'string' || appName.length === 0) return null;
    if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) return null;
    return { challenge, origin, appName, createdAt };
  } catch {
    return null;
  }
}

/** Load and shape-validate the pending redirect. Returns null if absent or malformed. */
export function loadPendingRedirect(): PendingRedirect | null {
  return shapePendingRedirect(safeGet(STORAGE_KEYS.pendingRedirect));
}

/** Async-storage variant of `loadPendingRedirect`. */
export async function loadPendingRedirectFromStorage(storage?: SignetStorage): Promise<PendingRedirect | null> {
  const raw = await safeGetFrom(storage, STORAGE_KEYS.pendingRedirect);
  const pending = shapePendingRedirect(raw);
  if (storage?.required && raw !== null && !pending) throw new Error('required-storage-invalid-pending-redirect');
  if (storage?.required && pending) pendingReceipts.set(pending, {storage, raw:raw!});
  return pending;
}

/** Clear the pending-redirect record. Safe to call when none exists. */
export function clearPendingRedirect(): void {
  safeRemove(STORAGE_KEYS.pendingRedirect);
}

/** Async-storage variant of `clearPendingRedirect`. */
export async function clearPendingRedirectFromStorage(storage?: SignetStorage, expected?: PendingRedirect | null): Promise<void> {
  if (storage?.required) await removePending(storage, STORAGE_KEYS.pendingRedirect,
    expected === undefined ? await loadPendingRedirectFromStorage(storage) : expected);
  else await safeRemoveFrom(storage, STORAGE_KEYS.pendingRedirect);
}

// ── Pending relay (cross-device) sign-in persistence ──────────────────────────

function isPendingRelayAuth(value: unknown): value is PendingRelayAuth {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.challenge === 'string' && /^[0-9a-f]{64}$/i.test(v.challenge) &&
    typeof v.origin === 'string' && v.origin.length > 0 &&
    typeof v.appName === 'string' &&
    typeof v.relayUrl === 'string' && v.relayUrl.length > 0 &&
    (v.relayUrls === undefined || (Array.isArray(v.relayUrls) && v.relayUrls.length >= 1 && v.relayUrls.length <= 3 &&
      v.relayUrls.every(r => typeof r === 'string' && r.length > 0))) &&
    typeof v.sessionSkHex === 'string' && /^[0-9a-f]{64}$/i.test(v.sessionSkHex) &&
    typeof v.issuedAt === 'number' && Number.isFinite(v.issuedAt)
  );
}

/**
 * Persist the in-flight cross-device (relay) sign-in. Called immediately after
 * minting the session keypair so a page discarded while the user is in the
 * signer app can resume rather than losing the response.
 */
export async function savePendingRelayAuth(
  record: PendingRelayAuth,
  storage?: SignetStorage,
): Promise<void> {
  if (storage?.required) {
    if (!isPendingRelayAuth(record) || !validSecret(record.sessionSkHex)) throw new Error('required-storage-invalid-pending-relay');
    const existing = await loadPendingRelayAuth(storage);
    if (existing) throw new Error('required-storage-pending-conflict');
    await retainPending(storage, STORAGE_KEYS.pendingRelayAuth, record, JSON.stringify(record));
  } else await safeSetTo(storage, STORAGE_KEYS.pendingRelayAuth, JSON.stringify(record));
}

/**
 * Returns the in-flight sign-in, or null if there isn't one, it's malformed, or
 * its window has passed. An expired record is cleared on the way out — it can
 * never be resumed and its session key should not linger in storage.
 */
export async function loadPendingRelayAuth(
  storage?: SignetStorage,
): Promise<PendingRelayAuth | null> {
  const raw = await safeGetFrom(storage, STORAGE_KEYS.pendingRelayAuth);
  if (raw === null) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { /* Validated below. */ }
  if (!isPendingRelayAuth(parsed) || (storage?.required && !validSecret(parsed.sessionSkHex))) {
    if (storage?.required) throw new Error('required-storage-invalid-pending-relay');
    return null;
  }
  if (storage?.required) pendingReceipts.set(parsed, {storage, raw});
  if (Math.floor(Date.now() / 1000) > parsed.issuedAt + AUTH_FRESHNESS_WINDOW_SEC) {
    await clearPendingRelayAuth(storage, parsed);
    return null;
  }
  return parsed;
}

/** Clear the pending relay-auth record. Safe to call when none exists. */
export async function clearPendingRelayAuth(storage?: SignetStorage, expected?: PendingRelayAuth | null): Promise<void> {
  if (storage?.required) {
    // Read without expiry recursion; expiry itself supplies its captured record.
    let record = expected;
    if (record === undefined) {
      const raw = await safeGetFrom(storage, STORAGE_KEYS.pendingRelayAuth);
      if (raw === null) return;
      let parsed: unknown; try { parsed = JSON.parse(raw); } catch { /* Hold below. */ }
      if (!isPendingRelayAuth(parsed) || !validSecret(parsed.sessionSkHex)) throw new Error('required-storage-invalid-pending-relay');
      pendingReceipts.set(parsed, {storage, raw}); record = parsed;
    }
    await removePending(storage, STORAGE_KEYS.pendingRelayAuth, record);
  } else await safeRemoveFrom(storage, STORAGE_KEYS.pendingRelayAuth);
}

// ── Hex helpers (avoid pulling in @noble for two functions) ───────────────────

export function bytesToHexLocal(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytesLocal(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd-hex-length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
