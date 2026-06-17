/**
 * localStorage persistence for signet-login sessions.
 *
 * Storage keys are namespaced under `signet:login.*` so they don't collide
 * with `signet:verify.*` or any future Signet SDK.
 */
import type { LoginMethod, PendingRedirect, SignetStorage } from './types.js';
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
/** Save a session. Caller must serialise authEvent to JSON. */
export declare function saveSession(s: PersistedSession): void;
/** Async-storage variant of `saveSession`. */
export declare function saveSessionToStorage(s: PersistedSession, storage?: SignetStorage): Promise<void>;
/** Load a session if one is present. Returns null if no session or it's malformed. */
export declare function loadSession(): PersistedSession | null;
/** Async-storage variant of `loadSession`. */
export declare function loadSessionFromStorage(storage?: SignetStorage): Promise<PersistedSession | null>;
/** Clear all signet-login keys. Does not touch other Signet SDK storage.
 *
 * Note: `clientSk` (the persistent NIP-46 client identity, see
 * `loadOrCreatePersistentClientSk`) is deliberately NOT cleared. It is the
 * browser's stable transport identity to bunkers, not session state — keeping
 * it means a re-login presents the same client pubkey and stays auto-approved
 * by the signer. Use `clearPersistentClientSk` for an explicit reset. */
export declare function clearSession(): void;
/** Async-storage variant of `clearSession`. */
export declare function clearSessionFromStorage(storage?: SignetStorage): Promise<void>;
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
export declare function loadOrCreatePersistentClientSk(): Uint8Array;
/** Async-storage variant of `loadOrCreatePersistentClientSk`. */
export declare function loadOrCreatePersistentClientSkFromStorage(storage?: SignetStorage): Promise<Uint8Array>;
/** Forget the persistent client key, forcing a fresh one on next connect. */
export declare function clearPersistentClientSk(): void;
/** Async-storage variant of `clearPersistentClientSk`. */
export declare function clearPersistentClientSkFromStorage(storage?: SignetStorage): Promise<void>;
/**
 * Persist the in-flight redirect state. Called immediately before navigating
 * to signet-app so the callback consumer can validate the round-trip.
 *
 * Stored as a single JSON blob under `signet:login.pendingRedirect`. We keep
 * it in localStorage rather than sessionStorage because some browsers (older
 * iOS Safari especially) wipe sessionStorage on cross-origin navigation.
 */
export declare function savePendingRedirect(p: PendingRedirect): void;
/** Async-storage variant of `savePendingRedirect`. */
export declare function savePendingRedirectToStorage(p: PendingRedirect, storage?: SignetStorage): Promise<void>;
/** Load and shape-validate the pending redirect. Returns null if absent or malformed. */
export declare function loadPendingRedirect(): PendingRedirect | null;
/** Async-storage variant of `loadPendingRedirect`. */
export declare function loadPendingRedirectFromStorage(storage?: SignetStorage): Promise<PendingRedirect | null>;
/** Clear the pending-redirect record. Safe to call when none exists. */
export declare function clearPendingRedirect(): void;
/** Async-storage variant of `clearPendingRedirect`. */
export declare function clearPendingRedirectFromStorage(storage?: SignetStorage): Promise<void>;
export declare function bytesToHexLocal(bytes: Uint8Array): string;
export declare function hexToBytesLocal(hex: string): Uint8Array;
