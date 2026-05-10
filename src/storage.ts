/**
 * localStorage persistence for signet-login sessions.
 *
 * Storage keys are namespaced under `signet:login.*` so they don't collide
 * with `signet:verify.*` or any future Signet SDK.
 */

import type { LoginMethod, PendingRedirect, SignetAuthEvent } from './types.js';
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

/** Save a session. Caller must serialise authEvent to JSON. */
export function saveSession(s: PersistedSession): void {
  safeSet(STORAGE_KEYS.pubkey, s.pubkey);
  safeSet(STORAGE_KEYS.method, s.method);
  safeSet(STORAGE_KEYS.authEvent, s.authEventJson);
  if (s.bunkerUri !== undefined) safeSet(STORAGE_KEYS.bunkerUri, s.bunkerUri);
  if (s.bunkerClientSkHex !== undefined) safeSet(STORAGE_KEYS.bunkerClientSk, s.bunkerClientSkHex);
  if (s.expiresAt !== undefined) safeSet(STORAGE_KEYS.expiresAt, String(s.expiresAt));
  if (s.displayName !== undefined) safeSet(STORAGE_KEYS.displayName, s.displayName);
}

/** Load a session if one is present. Returns null if no session or it's malformed. */
export function loadSession(): PersistedSession | null {
  const pubkey = safeGet(STORAGE_KEYS.pubkey);
  const method = safeGet(STORAGE_KEYS.method) as LoginMethod | null;
  const authEventJson = safeGet(STORAGE_KEYS.authEvent);
  if (!pubkey || !method || !authEventJson) return null;
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) return null;
  if (method !== 'nip07' && method !== 'redirect' && method !== 'bunker' && method !== 'amber') return null;

  // Sanity-parse the auth event before returning
  let authEvent: SignetAuthEvent;
  try {
    authEvent = JSON.parse(authEventJson);
    if (typeof authEvent !== 'object' || authEvent === null) return null;
    if (authEvent.pubkey !== pubkey) return null;
  } catch {
    return null;
  }

  const expiresAtRaw = safeGet(STORAGE_KEYS.expiresAt);
  const expiresAt = expiresAtRaw ? Number(expiresAtRaw) : undefined;
  if (expiresAt !== undefined && Number.isFinite(expiresAt) && Date.now() > expiresAt) {
    // Session expired — drop it
    clearSession();
    return null;
  }

  const result: PersistedSession = { pubkey, method, authEventJson };
  const bunkerUri = safeGet(STORAGE_KEYS.bunkerUri);
  const bunkerClientSkHex = safeGet(STORAGE_KEYS.bunkerClientSk);
  const displayName = safeGet(STORAGE_KEYS.displayName);
  if (bunkerUri) result.bunkerUri = bunkerUri;
  if (bunkerClientSkHex) result.bunkerClientSkHex = bunkerClientSkHex;
  if (expiresAt !== undefined && Number.isFinite(expiresAt)) result.expiresAt = expiresAt;
  if (displayName) result.displayName = displayName;
  return result;
}

/** Clear all signet-login keys. Does not touch other Signet SDK storage. */
export function clearSession(): void {
  safeRemove(STORAGE_KEYS.pubkey);
  safeRemove(STORAGE_KEYS.method);
  safeRemove(STORAGE_KEYS.authEvent);
  safeRemove(STORAGE_KEYS.bunkerUri);
  safeRemove(STORAGE_KEYS.bunkerClientSk);
  safeRemove(STORAGE_KEYS.expiresAt);
  safeRemove(STORAGE_KEYS.displayName);
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

/** Load and shape-validate the pending redirect. Returns null if absent or malformed. */
export function loadPendingRedirect(): PendingRedirect | null {
  const raw = safeGet(STORAGE_KEYS.pendingRedirect);
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

/** Clear the pending-redirect record. Safe to call when none exists. */
export function clearPendingRedirect(): void {
  safeRemove(STORAGE_KEYS.pendingRedirect);
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
