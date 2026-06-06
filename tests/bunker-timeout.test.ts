/**
 * Regression test for the `createBunkerSigner` timeout guard.
 *
 * This deliberately does NOT exercise the real NIP-46 round-trip (that stays
 * integration-only, per signers.test.ts). It covers only the timeout wrapper:
 * nostr-tools' `BunkerSigner.sendRequest` has no per-request timeout, so a
 * remote signer that never replies hangs `connect()`/`getPublicKey()` forever.
 * That is exactly what happens to the redirect-bunker auto-pair when signet-app
 * hands over a `bunker://` URI for its own in-page NIP-46 server and then a
 * same-tab redirect navigates that server away before the consumer connects —
 * the consumer's boot stalled on a blank screen. `timeoutMs` must race the
 * handshake, close the half-open signer, and reject.
 */
import { describe, it, expect, vi } from 'vitest';

const h = vi.hoisted(() => ({
  close: vi.fn(async () => {}),
  state: { connect: (async () => {}) as () => Promise<void> },
}));

vi.mock('nostr-tools/nip46', () => ({
  parseBunkerInput: async () => ({
    pubkey: 'b'.repeat(64),
    relays: ['wss://relay.test'],
    secret: 'sekret',
  }),
  BunkerSigner: {
    fromBunker: () => ({
      connect: () => h.state.connect(),
      getPublicKey: async () => 'b'.repeat(64),
      close: h.close,
    }),
  },
}));

import { createBunkerSigner } from '../src/signers.js';

const URI = `bunker://${'b'.repeat(64)}?relay=wss://relay.test&secret=sekret`;
const NEVER = (): Promise<void> => new Promise<void>(() => {});

describe('createBunkerSigner timeout guard', () => {
  it('rejects with bunker-connect-timeout and closes the signer when the handshake hangs', async () => {
    h.close.mockClear();
    h.state.connect = NEVER;
    await expect(createBunkerSigner({ uri: URI, timeoutMs: 30 })).rejects.toThrow('bunker-connect-timeout');
    expect(h.close).toHaveBeenCalled();
  });

  it('resolves normally when the handshake completes before the deadline', async () => {
    h.close.mockClear();
    h.state.connect = async () => {};
    const signer = await createBunkerSigner({ uri: URI, timeoutMs: 1000 });
    expect(signer.pubkey).toBe('b'.repeat(64));
    expect(h.close).not.toHaveBeenCalled();
  });

  it('does not arm a timeout when timeoutMs is omitted (opt-in only)', async () => {
    h.close.mockClear();
    h.state.connect = NEVER;
    const pending = createBunkerSigner({ uri: URI });
    const sentinel = Symbol('still-pending');
    const winner = await Promise.race([
      pending.then(() => 'settled', () => 'settled'),
      new Promise(resolve => setTimeout(() => resolve(sentinel), 60)),
    ]);
    expect(winner).toBe(sentinel);
    expect(h.close).not.toHaveBeenCalled();
  });
});
