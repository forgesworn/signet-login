/**
 * Signet Login SDK — Sign in with Signet for Nostr-aware websites.
 *
 * ESM / bundler usage:
 *   import { login, restoreSession, logout } from 'signet-login';
 *
 * Script-tag / IIFE usage (additively extends `window.Signet`):
 *   <script src="https://cdn.signet.forgesworn.dev/signet-login.iife.js"></script>
 *   <script>
 *     const session = await Signet.login({ appName: 'Asteroid Sats' });
 *   </script>
 *
 * The IIFE bundle does NOT overwrite `window.Signet` — it augments whatever is
 * already there (so `signet-verify.iife.js` and `signet-login.iife.js` coexist
 * in either load order on the same page).
 */

export type {
  NostrEvent,
  EventTemplate,
  LoginMethod,
  SignerCapabilities,
  SignetSigner,
  SignetAuthEvent,
  SignetSession,
  LoginOptions,
  RestoreOptions,
} from './types.js';

import type {
  LoginOptions,
  RestoreOptions,
  SignetSession,
  SignetAuthEvent,
} from './types.js';
import { showLoginModal } from './modal.js';
import { saveSession, loadSession, clearSession, bytesToHexLocal, hexToBytesLocal } from './storage.js';
import {
  hasNip07,
  createNip07Signer,
  createBunkerSigner,
  EphemeralSigner,
} from './signers.js';

import { handleCallback } from './callback.js';
export { handleCallback };
export type { CallbackResult } from './callback.js';

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Show the login picker and resolve to a SignetSession on success, or null on
 * cancel / timeout.
 */
export async function login(opts: LoginOptions): Promise<SignetSession | null> {
  const session = await showLoginModal(opts);
  if (!session) return null;

  if (opts.persist !== false) {
    persistSession(session);
  }

  return session;
}

/**
 * Try to restore a session from localStorage. Returns null if no session is
 * stored or it's malformed/expired.
 *
 * For bunker sessions, attempts to reconnect using the stored URI + client SK.
 * If the bunker is unreachable, returns null and clears the stored session.
 */
export async function restoreSession(opts?: RestoreOptions): Promise<SignetSession | null> {
  const stored = loadSession();
  if (!stored) return null;

  let authEvent: SignetAuthEvent;
  try {
    authEvent = JSON.parse(stored.authEventJson);
  } catch {
    clearSession();
    return null;
  }

  if (stored.method === 'nip07') {
    if (!hasNip07()) {
      // Extension was uninstalled — return ephemeral identity-only session
      const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
      return {
        pubkey: stored.pubkey,
        method: 'redirect', // downgrade — caller sees "no signing"
        signer: ephemeral,
        authEvent,
      };
    }
    try {
      const signer = await createNip07Signer();
      // Verify the same pubkey is selected — extension may have switched accounts
      if (signer.pubkey !== stored.pubkey) {
        clearSession();
        return null;
      }
      return {
        pubkey: stored.pubkey,
        method: 'nip07',
        signer,
        authEvent,
      };
    } catch {
      clearSession();
      return null;
    }
  }

  if (stored.method === 'bunker') {
    if (opts?.reconnectBunker === false) {
      const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
      return {
        pubkey: stored.pubkey,
        method: 'redirect',
        signer: ephemeral,
        authEvent,
      };
    }
    if (!stored.bunkerUri || !stored.bunkerClientSkHex) {
      clearSession();
      return null;
    }
    try {
      const sk = hexToBytesLocal(stored.bunkerClientSkHex);
      const signer = await createBunkerSigner({ uri: stored.bunkerUri, clientSecretKey: sk });
      if (signer.pubkey !== stored.pubkey) {
        await signer.close();
        clearSession();
        return null;
      }
      return {
        pubkey: stored.pubkey,
        method: 'bunker',
        signer,
        authEvent,
      };
    } catch {
      clearSession();
      return null;
    }
  }

  // method === 'redirect' — restore as ephemeral (auth-only)
  const ephemeral = new EphemeralSigner(stored.pubkey, authEvent);
  const session: SignetSession = {
    pubkey: stored.pubkey,
    method: 'redirect',
    signer: ephemeral,
    authEvent,
  };
  if (stored.displayName) session.displayName = stored.displayName;
  return session;
}

/**
 * Clear the stored session and close the active signer.
 */
export async function logout(currentSession?: SignetSession): Promise<void> {
  if (currentSession) {
    try { await currentSession.signer.close(); } catch { /* ignore */ }
  }
  clearSession();
}

// ── Persistence helpers (internal) ────────────────────────────────────────────

function persistSession(session: SignetSession): void {
  const payload: Parameters<typeof saveSession>[0] = {
    pubkey: session.pubkey,
    method: session.method,
    authEventJson: JSON.stringify(session.authEvent),
  };

  if (session.method === 'bunker') {
    // Cast: in bunker mode, the signer is a BunkerSignerImpl with bunkerUri + clientSecretKey
    const bunkerSigner = session.signer as unknown as {
      bunkerUri?: string;
      clientSecretKey?: Uint8Array;
    };
    if (bunkerSigner.bunkerUri && bunkerSigner.clientSecretKey instanceof Uint8Array) {
      payload.bunkerUri = bunkerSigner.bunkerUri;
      payload.bunkerClientSkHex = bytesToHexLocal(bunkerSigner.clientSecretKey);
    }
  }

  if (session.expiresAt !== undefined) payload.expiresAt = session.expiresAt;
  if (session.displayName !== undefined) payload.displayName = session.displayName;

  saveSession(payload);
}

// ── Auto-attach to window.Signet (additive) ───────────────────────────────────

if (typeof window !== 'undefined') {
  // Never overwrite — additive only. Coexists with signet-verify on the same page.
  const existing = (window as unknown as { Signet?: Record<string, unknown> }).Signet;
  const SignetGlobal = existing ?? {};
  Object.assign(SignetGlobal, { login, restoreSession, logout, handleCallback });
  (window as unknown as { Signet: Record<string, unknown> }).Signet = SignetGlobal;
}
