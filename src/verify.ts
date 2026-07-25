/**
 * Server-side verifier for Signet auth events.
 *
 * Run on your server when the client posts a SignetAuthEvent — this verifies
 * the schnorr signature, the canonical event ID, and the embedded challenge /
 * origin / app tags. Pure Node-friendly: no DOM, no relays, no fetch.
 *
 *   import { verifyLogin } from 'signet-login/verify';
 *   const result = verifyLogin(authEvent, {
 *     expectedChallenge: '...',
 *     expectedOrigin: 'https://mygame.com',
 *     expectedAppName: 'Asteroid Sats',
 *   });
 */

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

import type { SignetAuthEvent } from './types.js';

export interface VerifyLoginOptions {
  /**
   * The challenge the consumer issued. 64 hex.
   *
   * This must be a nonce YOUR SERVER generated, stored, and has not accepted
   * before — `verifyLogin` keeps no state, so it cannot tell a fresh proof
   * from one replayed inside the `maxAgeSeconds` window. Issue it, record it
   * against the pending login, and delete it the moment this call returns
   * valid. A second proof bearing the same challenge must be rejected.
   *
   * In particular, do not verify against a challenge the browser chose.
   * `login()` and `createLoginAuthEvent()` auto-generate one when you omit
   * `challenge`, which is fine for a client-only app but proves nothing to a
   * server: an attacker replaying a captured auth event supplies the matching
   * challenge along with it. See the README's server-side verification
   * section.
   */
  expectedChallenge: string;
  /** The origin the auth event must be bound to (e.g. 'https://mygame.com'). */
  expectedOrigin: string;
  /**
   * Optional: the app name the consumer claimed at login time. If supplied,
   * the auth event's `app` tag must match.
   */
  expectedAppName?: string;
  /** Maximum age of the auth event in seconds. Default: 300 (5 min). */
  maxAgeSeconds?: number;
  /** Override Date.now() for testing. */
  now?: () => number;
}

export type VerifyLoginResult =
  | { valid: true; pubkey: string; createdAt: number }
  | { valid: false; error: VerifyLoginError };

export type VerifyLoginError =
  | 'malformed-event'
  | 'wrong-kind'
  | 'invalid-event-id'
  | 'invalid-signature'
  | 'challenge-mismatch'
  | 'origin-mismatch'
  | 'app-mismatch'
  | 'too-old'
  | 'in-the-future';

export type LoginAuthValidationError = VerifyLoginError | 'pubkey-mismatch';

export interface ValidateLoginAuthEventOptions extends VerifyLoginOptions {
  /** Optional signer/session pubkey the auth proof must belong to. */
  expectedPubkey?: string;
}

export type LoginAuthValidationResult =
  | { valid: true; pubkey: string; createdAt: number }
  | { valid: false; error: LoginAuthValidationError };

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function isHex(s: unknown, len: number): s is string {
  return typeof s === 'string' && new RegExp(`^[0-9a-f]{${len}}$`, 'i').test(s);
}

function getTag(tags: unknown, key: string): string | undefined {
  if (!Array.isArray(tags)) return undefined;
  const tag = tags.find(t => Array.isArray(t) && t[0] === key && typeof t[1] === 'string');
  return tag ? (tag[1] as string) : undefined;
}

/**
 * Canonical Nostr event ID computation per NIP-01:
 *   id = SHA-256(JSON.stringify([0, pubkey, created_at, kind, tags, content]))
 */
function computeEventId(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  const serialised = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return bytesToHex(sha256(new TextEncoder().encode(serialised)));
}

/**
 * Verify a Signet kind-21236 auth event against the expected challenge, origin,
 * and (optionally) app name.
 */
export function verifyLogin(
  event: unknown,
  opts: VerifyLoginOptions,
): VerifyLoginResult {
  // Structural validation
  if (typeof event !== 'object' || event === null) return { valid: false, error: 'malformed-event' };
  const e = event as Record<string, unknown>;
  if (!isHex(e.id, 64)) return { valid: false, error: 'malformed-event' };
  if (!isHex(e.pubkey, 64)) return { valid: false, error: 'malformed-event' };
  if (!isHex(e.sig, 128)) return { valid: false, error: 'malformed-event' };
  if (typeof e.created_at !== 'number') return { valid: false, error: 'malformed-event' };
  if (typeof e.content !== 'string') return { valid: false, error: 'malformed-event' };
  if (!Array.isArray(e.tags)) return { valid: false, error: 'malformed-event' };

  if (e.kind !== 21236) return { valid: false, error: 'wrong-kind' };

  const ev = e as unknown as SignetAuthEvent;

  // Verify event ID = SHA-256 of canonical serialisation
  const expectedId = computeEventId({
    pubkey: ev.pubkey,
    created_at: ev.created_at,
    kind: 21236,
    tags: ev.tags,
    content: ev.content,
  });
  if (expectedId !== ev.id.toLowerCase()) return { valid: false, error: 'invalid-event-id' };

  // Verify schnorr signature
  let sigOk = false;
  try {
    sigOk = schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { valid: false, error: 'invalid-signature' };

  // Challenge tag
  const challengeTag = getTag(ev.tags, 'challenge');
  if (!challengeTag) return { valid: false, error: 'challenge-mismatch' };
  if (!isHex(opts.expectedChallenge, 64)) return { valid: false, error: 'challenge-mismatch' };
  if (challengeTag.toLowerCase() !== opts.expectedChallenge.toLowerCase()) {
    return { valid: false, error: 'challenge-mismatch' };
  }

  // Origin tag
  const originTag = getTag(ev.tags, 'origin');
  if (!originTag || originTag !== opts.expectedOrigin) {
    return { valid: false, error: 'origin-mismatch' };
  }

  // App tag (optional check)
  if (opts.expectedAppName !== undefined) {
    const appTag = getTag(ev.tags, 'app');
    if (appTag !== opts.expectedAppName) {
      return { valid: false, error: 'app-mismatch' };
    }
  }

  // Freshness
  const now = (opts.now ?? Date.now)() / 1000;
  const maxAge = opts.maxAgeSeconds ?? 300;
  const age = now - ev.created_at;
  if (age > maxAge) return { valid: false, error: 'too-old' };
  // Allow 60 seconds of clock skew into the future
  if (age < -60) return { valid: false, error: 'in-the-future' };

  return { valid: true, pubkey: ev.pubkey.toLowerCase(), createdAt: ev.created_at };
}

export function validateLoginAuthEvent(
  authEvent: unknown,
  opts: ValidateLoginAuthEventOptions,
): LoginAuthValidationResult {
  const result = verifyLogin(authEvent, opts);
  if (!result.valid) return result;

  if (opts.expectedPubkey !== undefined && result.pubkey !== opts.expectedPubkey.toLowerCase()) {
    return { valid: false, error: 'pubkey-mismatch' };
  }

  return result;
}

export function assertValidLoginAuthEvent(
  authEvent: SignetAuthEvent,
  opts: ValidateLoginAuthEventOptions,
): SignetAuthEvent {
  const result = validateLoginAuthEvent(authEvent, opts);
  if (!result.valid) {
    throw new Error(`auth-event-invalid:${result.error}`);
  }
  return authEvent;
}
