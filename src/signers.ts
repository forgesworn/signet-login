/**
 * Three signer implementations behind one interface.
 *
 *   Nip07Signer       — wraps window.nostr (bark, Alby, nos2x, Flamingo, …)
 *   BunkerSignerImpl  — wraps nostr-tools BunkerSigner (NIP-46 over relay)
 *   EphemeralSigner   — auth-only fallback when only the redirect signature is available
 */

import type { EventTemplate, NostrEvent, SignetSigner, SignerCapabilities, SignetAuthEvent } from './types.js';
import { BunkerSigner, parseBunkerInput, type BunkerPointer } from 'nostr-tools/nip46';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { decode as nip19Decode } from 'nostr-tools/nip19';
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44';

// ── NIP-07 ────────────────────────────────────────────────────────────────────

/** The shape of `window.nostr` exposed by NIP-07 extensions. */
interface Nip07Provider {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<NostrEvent>;
  nip44?: {
    encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  };
}

declare global {
  interface Window {
    nostr?: Nip07Provider;
  }
}

/** Returns true if a NIP-07 extension is present on the page. */
export function hasNip07(): boolean {
  return typeof window !== 'undefined' && !!window.nostr && typeof window.nostr.signEvent === 'function';
}

export class Nip07Signer implements SignetSigner {
  readonly method = 'nip07' as const;
  readonly capabilities: SignerCapabilities;
  readonly nip44?: SignetSigner['nip44'];

  constructor(public readonly pubkey: string, private readonly provider: Nip07Provider) {
    this.capabilities = { canSignEvents: true, hasNip44: !!provider.nip44 };
    if (provider.nip44) {
      this.nip44 = {
        encrypt: (peer, pt) => provider.nip44!.encrypt(peer, pt),
        decrypt: (peer, ct) => provider.nip44!.decrypt(peer, ct),
      };
    }
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    return this.provider.signEvent(template);
  }

  async close(): Promise<void> {
    // NIP-07 extensions have no concept of disconnect — nothing to do.
  }
}

/** Connects to the page's NIP-07 provider and returns a Nip07Signer. */
export async function createNip07Signer(): Promise<Nip07Signer> {
  if (!hasNip07()) throw new Error('no-nip07-provider');
  const provider = window.nostr!;
  const pubkey = await provider.getPublicKey();
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('invalid-pubkey-from-nip07');
  return new Nip07Signer(pubkey.toLowerCase(), provider);
}

// ── NIP-46 bunker ─────────────────────────────────────────────────────────────

/** Wraps nostr-tools' BunkerSigner with our SignetSigner interface. */
export class BunkerSignerImpl implements SignetSigner {
  readonly method = 'bunker' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: true, hasNip44: true };
  readonly nip44: SignetSigner['nip44'];

  constructor(
    public readonly pubkey: string,
    private readonly bunker: BunkerSigner,
    /** Original bunker URI — kept for persistence/reconnect. */
    public readonly bunkerUri: string,
    /** The 32-byte client secret key used in this session — kept for reconnect. */
    public readonly clientSecretKey: Uint8Array,
  ) {
    this.nip44 = {
      encrypt: (peer, pt) => bunker.nip44Encrypt(peer, pt),
      decrypt: (peer, ct) => bunker.nip44Decrypt(peer, ct),
    };
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    // BunkerSigner.signEvent expects EventTemplate with required created_at + tags.
    // Strip any pubkey field, fill in defaults if omitted.
    const { pubkey: _omit, ...rest } = template as EventTemplate & { pubkey?: string };
    void _omit;
    const filled = {
      kind: rest.kind,
      content: rest.content,
      created_at: rest.created_at ?? Math.floor(Date.now() / 1000),
      tags: rest.tags ?? [],
    };
    const verified = await this.bunker.signEvent(filled);
    return verified as NostrEvent;
  }

  async close(): Promise<void> {
    await this.bunker.close();
  }
}

/**
 * Connect a bunker session from a `bunker://` or `nostr+connect://` URI (or a
 * NIP-05 identifier). Generates a fresh client secret key for the session.
 */
export async function createBunkerSigner(input: {
  uri: string;
  clientSecretKey?: Uint8Array;
  onauth?: (url: string) => void;
}): Promise<BunkerSignerImpl> {
  const trimmed = input.uri.trim();
  if (!trimmed) throw new Error('empty-bunker-uri');

  const pointer: BunkerPointer | null = await parseBunkerInput(trimmed);
  if (!pointer) throw new Error('invalid-bunker-uri');

  const sk = input.clientSecretKey ?? generateSecretKey();
  if (sk.length !== 32) throw new Error('invalid-client-secret-key');

  const bunker = BunkerSigner.fromBunker(sk, pointer, { onauth: input.onauth });
  await bunker.connect();
  const pubkey = await bunker.getPublicKey();
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
    await bunker.close().catch(() => {});
    throw new Error('invalid-pubkey-from-bunker');
  }

  return new BunkerSignerImpl(pubkey.toLowerCase(), bunker, trimmed, sk);
}

/** Generate a 32-byte secret key. */
export function generateSecretKey(): Uint8Array {
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
export class LocalSigner implements SignetSigner {
  readonly method = 'nsec' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: true, hasNip44: true };
  readonly nip44: SignetSigner['nip44'];

  constructor(public readonly pubkey: string, private readonly privkey: Uint8Array) {
    this.nip44 = {
      encrypt: async (peer, pt) => nip44Encrypt(pt, getConversationKey(this.privkey, peer)),
      decrypt: async (peer, ct) => nip44Decrypt(ct, getConversationKey(this.privkey, peer)),
    };
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    const filled = {
      kind: template.kind,
      content: template.content,
      created_at: template.created_at ?? Math.floor(Date.now() / 1000),
      tags: template.tags ?? [],
    };
    return finalizeEvent(filled, this.privkey) as NostrEvent;
  }

  async close(): Promise<void> {
    // Best-effort wipe — the engine may already have copies in CoW pages, but
    // zeroing here at least gives a consistent shape with bunker.close().
    this.privkey.fill(0);
  }
}

/**
 * Decode a bech32 nsec into a LocalSigner. Accepts either the `nsec1...`
 * prefix or a raw 64-char hex private key for power-user paste paths.
 * Throws on any malformed input — caller surfaces the error to the user.
 */
export function createLocalSignerFromNsec(input: string): LocalSigner {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('empty-nsec');

  let sk: Uint8Array;
  if (trimmed.startsWith('nsec1')) {
    const decoded = nip19Decode(trimmed);
    if (decoded.type !== 'nsec') throw new Error('not-an-nsec');
    sk = decoded.data as Uint8Array;
  } else if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    sk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) sk[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  } else {
    throw new Error('invalid-nsec-format');
  }
  if (sk.length !== 32) throw new Error('invalid-nsec-length');

  const pubkey = getPublicKey(sk);
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('invalid-pubkey-from-nsec');
  return new LocalSigner(pubkey.toLowerCase(), sk);
}

// ── Ephemeral (redirect-only) ─────────────────────────────────────────────────

/**
 * Auth-only signer returned by the redirect/QR flow before Option B is built.
 * Holds the signed challenge but cannot sign further events.
 */
export class EphemeralSigner implements SignetSigner {
  readonly method = 'redirect' as const;
  readonly capabilities: SignerCapabilities = { canSignEvents: false, hasNip44: false };

  constructor(public readonly pubkey: string, public readonly authEvent: SignetAuthEvent) {}

  async signEvent(_template: EventTemplate): Promise<NostrEvent> {
    throw new Error(
      'signer-auth-only: this session was established via redirect and cannot sign new events. ' +
      'Install a NIP-07 extension (bark, Alby) or paste a bunker URI to upgrade.',
    );
  }

  async close(): Promise<void> {
    // nothing to close
  }
}
