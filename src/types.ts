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
export type LoginMethod = 'nip07' | 'redirect' | 'bunker' | 'nsec' | 'amber';

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

/**
 * Delivery mode for the "Sign in with Signet" method.
 *
 * - 'relay' (default): the modal shows a QR / link, signet-app gift-wraps the
 *   signed auth event back via a Nostr relay. The current tab stays put. Best
 *   for desktop where users have a phone alongside.
 *
 * - 'redirect': the current tab navigates to signet-app, the user signs in
 *   there, signet-app redirects the same tab back to `redirectCallback` with
 *   auth params in the query string. The consumer must call
 *   `Signet.handleCallback()` on boot to consume the params and resolve a
 *   session. Best for mobile / single-device flows.
 *
 * Only affects the 'redirect' login method. NIP-07 and bunker are unchanged.
 */
export type SignetDeliveryMode = 'relay' | 'redirect';

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
   * Callback URL used by the same-device redirect path. Must be same-origin
   * as the calling page. Defaults to `${origin}/`. Only used when `mode` is
   * 'redirect'.
   */
  redirectCallback?: string;
  /**
   * Delivery mode for the Sign in with Signet method. See `SignetDeliveryMode`.
   * Default: 'relay'.
   *
   * In 'redirect' mode `Signet.login()` navigates the current tab away and
   * never resolves in this tab — the returned promise is abandoned. Wire up
   * `Signet.handleCallback()` on boot to receive the session on return.
   */
  mode?: SignetDeliveryMode;
  /** Persist the session to localStorage. Default: true. */
  persist?: boolean;
}

/**
 * State persisted to localStorage between starting a redirect and consuming
 * the callback. Used by `consumeCallback()` to validate the round-trip and
 * reconstruct the kind-21236 auth event.
 */
export interface PendingRedirect {
  /** 64-hex challenge issued at login start — must match the auth event tag. */
  challenge: string;
  /** Origin that initiated the login — must match `window.location.origin` on return. */
  origin: string;
  /** App name — used to reconstruct the `app` tag on the auth event. */
  appName: string;
  /** Unix-ms when the redirect started. Used for the freshness window. */
  createdAt: number;
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
  mode: 'relay' as SignetDeliveryMode,
};

/**
 * Pending redirect must be consumed within this window of starting it,
 * otherwise the callback is treated as stale (likely a stray bookmark or
 * tab restored after a long pause). Mirrors signet-app's URL freshness
 * window (5 min) so callback consumers behave consistently with the issuer.
 */
export const PENDING_REDIRECT_TTL_MS = 5 * 60 * 1000;

/** Storage keys, namespaced under signet:login.* */
export const STORAGE_KEYS = {
  pubkey: 'signet:login.pubkey',
  method: 'signet:login.method',
  authEvent: 'signet:login.authEvent',
  bunkerUri: 'signet:login.bunkerUri',
  bunkerClientSk: 'signet:login.bunkerClientSk',
  /**
   * Persistent NIP-46 client secret key for this browser/origin. Unlike
   * `bunkerClientSk` (session-scoped, cleared on logout), this survives logout
   * so every bunker connect presents the SAME client pubkey. Bunkers (e.g.
   * Heartwood) auto-approve a single bound client pubkey per slot; minting a
   * fresh key per login made every request unbound and forced manual approval.
   */
  clientSk: 'signet:login.clientSk',
  expiresAt: 'signet:login.expiresAt',
  displayName: 'signet:login.displayName',
  /** Session-storage key for in-flight redirect state. */
  pendingRedirect: 'signet:login.pendingRedirect',
};
