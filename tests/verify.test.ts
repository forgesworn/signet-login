/**
 * Tests for the server-side verifier — sign a fake auth event and round-trip.
 */

import { describe, it, expect } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

import { verifyLogin } from '../src/verify.js';
import type { SignetAuthEvent } from '../src/types.js';

function makeAuthEvent(opts: {
  privKey: Uint8Array;
  challenge: string;
  origin: string;
  appName?: string;
  createdAt?: number;
  tamperKind?: number;
  tamperContent?: string;
}): SignetAuthEvent {
  const pubkey = bytesToHex(schnorr.getPublicKey(opts.privKey));
  const created_at = opts.createdAt ?? Math.floor(Date.now() / 1000);
  const tags: string[][] = [
    ['challenge', opts.challenge],
    ['origin', opts.origin],
  ];
  if (opts.appName) tags.push(['app', opts.appName]);

  const kind = opts.tamperKind ?? 21236;
  const content = opts.tamperContent ?? '';
  const serialised = JSON.stringify([0, pubkey, created_at, kind, tags, content]);
  const id = bytesToHex(sha256(new TextEncoder().encode(serialised)));
  const sig = bytesToHex(schnorr.sign(id, opts.privKey));

  return { id, pubkey, kind: kind as 21236, created_at, tags, content, sig };
}

describe('verifyLogin', () => {
  const privKey = schnorr.utils.randomPrivateKey();
  const challenge = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const origin = 'https://mygame.example';

  it('accepts a valid auth event', () => {
    const event = makeAuthEvent({ privKey, challenge, origin, appName: 'Test Game' });
    const result = verifyLogin(event, {
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedAppName: 'Test Game',
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.pubkey).toBe(bytesToHex(schnorr.getPublicKey(privKey)));
    }
  });

  it('rejects a wrong challenge', () => {
    const event = makeAuthEvent({ privKey, challenge, origin });
    const otherChallenge = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const result = verifyLogin(event, {
      expectedChallenge: otherChallenge,
      expectedOrigin: origin,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('challenge-mismatch');
  });

  it('rejects a wrong origin', () => {
    const event = makeAuthEvent({ privKey, challenge, origin });
    const result = verifyLogin(event, {
      expectedChallenge: challenge,
      expectedOrigin: 'https://other.example',
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('origin-mismatch');
  });

  it('rejects a wrong app name when supplied', () => {
    const event = makeAuthEvent({ privKey, challenge, origin, appName: 'A' });
    const result = verifyLogin(event, {
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedAppName: 'B',
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('app-mismatch');
  });

  it('passes when expectedAppName is omitted', () => {
    const event = makeAuthEvent({ privKey, challenge, origin, appName: 'X' });
    const result = verifyLogin(event, {
      expectedChallenge: challenge,
      expectedOrigin: origin,
    });
    expect(result.valid).toBe(true);
  });

  it('rejects wrong kind', () => {
    const event = makeAuthEvent({ privKey, challenge, origin, tamperKind: 1 });
    const result = verifyLogin(event, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('wrong-kind');
  });

  it('rejects tampered content (event id mismatch)', () => {
    const event = makeAuthEvent({ privKey, challenge, origin });
    const tampered = { ...event, content: 'modified' };
    const result = verifyLogin(tampered, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('invalid-event-id');
  });

  it('rejects tampered signature', () => {
    const event = makeAuthEvent({ privKey, challenge, origin });
    // Flip a bit in the signature without changing the id
    const sigBytes = Buffer.from(event.sig, 'hex');
    sigBytes[0] ^= 0x01;
    const tampered = { ...event, sig: sigBytes.toString('hex') };
    const result = verifyLogin(tampered, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('invalid-signature');
  });

  it('rejects an event older than the freshness window', () => {
    const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
    const event = makeAuthEvent({ privKey, challenge, origin, createdAt: oneHourAgo });
    const result = verifyLogin(event, {
      expectedChallenge: challenge,
      expectedOrigin: origin,
      maxAgeSeconds: 300,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('too-old');
  });

  it('rejects an event from the future beyond skew', () => {
    const oneHourAhead = Math.floor(Date.now() / 1000) + 3600;
    const event = makeAuthEvent({ privKey, challenge, origin, createdAt: oneHourAhead });
    const result = verifyLogin(event, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('in-the-future');
  });

  it('rejects a malformed event', () => {
    const result = verifyLogin({ not: 'an event' }, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe('malformed-event');
  });

  it('rejects null', () => {
    const result = verifyLogin(null, { expectedChallenge: challenge, expectedOrigin: origin });
    expect(result.valid).toBe(false);
  });
});
