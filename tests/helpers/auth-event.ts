import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

import type { SignetAuthEvent } from '../../src/types.js';

export const TEST_PRIVATE_KEY = new Uint8Array(32).fill(1);

export function makeAuthEvent(opts: {
  privKey?: Uint8Array;
  challenge: string;
  origin: string;
  appName?: string;
  createdAt?: number;
  extraTags?: string[][];
}): SignetAuthEvent {
  const privKey = opts.privKey ?? TEST_PRIVATE_KEY;
  const pubkey = bytesToHex(schnorr.getPublicKey(privKey));
  const created_at = opts.createdAt ?? Math.floor(Date.now() / 1000);
  const tags: string[][] = [
    ['challenge', opts.challenge],
    ['origin', opts.origin],
  ];
  if (opts.appName) tags.push(['app', opts.appName]);
  if (opts.extraTags) tags.push(...opts.extraTags);

  const content = '';
  const serialised = JSON.stringify([0, pubkey, created_at, 21236, tags, content]);
  const id = bytesToHex(sha256(new TextEncoder().encode(serialised)));
  const sig = bytesToHex(schnorr.sign(id, privKey));

  return {
    id,
    pubkey,
    kind: 21236,
    created_at,
    tags,
    content,
    sig,
  };
}

export function callbackSearchForAuthEvent(
  event: SignetAuthEvent,
  extras: Record<string, string> = {},
): string {
  const params = new URLSearchParams({
    pubkey: event.pubkey,
    signature: event.sig,
    eventId: event.id,
    t: String(event.created_at),
    ...extras,
  });
  return `?${params.toString()}`;
}
