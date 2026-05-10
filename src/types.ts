/**
 * Public types for signet-login.
 *
 * The SDK exposes a single SignetSigner interface that wraps three backends
 * (NIP-07 extension, NIP-46 bunker, ephemeral redirect-only). Consumers code
 * against the interface; the SDK picks the implementation based on user choice.
 */

/** A signed Nostr event. */
export interface NostrEvent {
  id: string;
  pubkey: string;
  kind: number;
  created_at: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** An unsigned event template ready for signing. */
export interface EventTemplate {
  kind: number;
  created_at?: number;
  tags?: string[][];
  content: string;
}

/** Login method actually used to authenticate. */
export type LoginMethod = 'nip07' | 'redirect' | 'bunker';

/** Capability flags exposed by a signer. */
export interface SignerCapabilities {
  /** True if the signer can sign arbitrary events going forward. False for redirect-auth-only sessions. */
  canSignEvents: boolean;
  /** True if NIP-44 encrypt/decrypt is available. */
  hasNip44: boolean;
}

/** Unified signer interface — three backends, one shape. */
export interface SignetSigner {
  readonly pubkey: string;
  readonly method: LoginMethod;
  readonly capabilities: SignerCapabilities;
  signEvent(template: EventTemplate): Promise<NostrEvent>;
  nip44?: {
    encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  };
  close(): Promise<void>;
}

/** A signed kind-21236 auth event proving pubkey ownership. */
export interface SignetAuthEvent extends NostrEvent {
  kind: 21236;
}

/** An authenticated session — pubkey + signer + the signed challenge proof. */
export interface SignetSession {
  pubkey: string;
  method: LoginMethod;
  signer: SignetSigner;
  /** The signed challenge event — proves identity, useful for server-side verification. */
  authEvent: SignetAuthEvent;
  /** Unix-ms expiry, if the session can expire (bunker tokens). Absent = session does not expire. */
  expiresAt?: number;
  /** Optional display name the user shared at approval (sanitised). */
  displayName?: string;
}

/** Options for Signet.login(). */
export interface LoginOptions {
  /** Required. Shown in the consent UI (e.g. "Asteroid Sats"). */
  appName: string;
  /** Optional 64-hex challenge. Auto-generated if omitted. */
  challenge?: string;
  /** Skip the picker and force a specific method. */
  preferredMethod?: LoginMethod;
  /** Relay URL for cross-device communication. Default: wss://relay.damus.io */
  relayUrl?: string;
  /** Modal colour scheme. Default: 'auto'. */
  theme?: 'light' | 'dark' | 'auto';
  /** Timeout in milliseconds. Default: 120_000. Clamped to [5_000, 600_000]. */
  timeout?: number;
  /**
   * Origin of the Signet app. Default: https://mysignet.app
   * Override for local development against your own signet-app instance.
   */
  signetAppOrigin?: string;
  /**
   * Callback URL used by the same-device redirect path. Must be on the same
   * origin as the calling page. If omitted, only the cross-device QR path is
   * offered for the redirect method.
   */
  redirectCallback?: string;
  /** Persist the session to localStorage. Default: true. */
  persist?: boolean;
}

/** Options for Signet.restoreSession(). */
export interface RestoreOptions {
  /** Reconnect a stored bunker session if present. Default: true. */
  reconnectBunker?: boolean;
  /** Default relay for bunker reconnection if URI omits it. */
  defaultRelay?: string;
}

/** Default values applied when the consumer omits an option. */
export const DEFAULTS = {
  relayUrl: 'wss://relay.damus.io',
  signetAppOrigin: 'https://mysignet.app',
  timeout: 120_000,
  theme: 'auto' as const,
  persist: true,
};

/** Storage keys, namespaced under signet:login.* */
export const STORAGE_KEYS = {
  pubkey: 'signet:login.pubkey',
  method: 'signet:login.method',
  authEvent: 'signet:login.authEvent',
  bunkerUri: 'signet:login.bunkerUri',
  bunkerClientSk: 'signet:login.bunkerClientSk',
  expiresAt: 'signet:login.expiresAt',
  displayName: 'signet:login.displayName',
  /** Session-storage key for in-flight redirect state. */
  pendingRedirect: 'signet:login.pendingRedirect',
};
