/**
 * Public types for signet-login.
 *
 * The SDK exposes a single SignetSigner interface across extension, Signet,
 * NIP-46, Android, and local fallback paths. Consumers code against the
 * interface; the SDK picks the implementation based on user choice.
 */

import { AUTH_FRESHNESS_WINDOW_SEC, DEFAULT_RELAY_URL } from 'signet-verify';

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

/** Method choices the login picker can show. Some choices resolve to the same session method. */
export type LoginPickerMethod =
  | LoginMethod
  | 'local-signet'
  | 'remote-signet'
  | 'qr'
  | 'nostrconnect';

/** Capability flags exposed by a signer. */
export interface SignerCapabilities {
  /** True if the signer can sign arbitrary events going forward. False for redirect-auth-only sessions. */
  canSignEvents: boolean;
  /** True if NIP-44 encrypt/decrypt is available. */
  hasNip44: boolean;
}

/** Unified signer interface — three backends, one shape. */
export interface SignerEffectBoundary {
  /** Check the caller's live native custody, then invoke start synchronously
   * inside that decision. Await provider settlement outside native locks.
   * Reject stale decisions; return the same result only after the caller's
   * handoff checks. No provider key or connection is exposed by this hook. */
  start<T>(provider: () => Promise<T>): Promise<T>;
}
/** A single explicit NIP-44 decrypt RPC. current() must synchronously
 * recheck its originating account/view/permission at every EVENT write.
 * Initial login, shared subscription frames and other methods are excluded. */
export interface Nip46DecryptBoundary extends SignerEffectBoundary {
  /** Explicit route-owned constructor; never infer a clearnet fallback. */
  readonly websocketImplementation: typeof WebSocket;
  current(): boolean;
}
/** Separate contract for guarded NIP-07 account discovery. */
export interface Nip07DiscoveryBoundary {
  readonly discoveryPreflightBoundary: 1;
  /** Run prepare outside native authority, then freshly validate native
   * custody and invoke effect synchronously inside that decision. No await
   * or provider metadata access belongs between the decision and effect.
   * Join the provider outside the native callback and validate its handoff. */
  start<T>(prepare: () => void, effect: () => Promise<T>): Promise<T>;
}
export interface SignetSigner {
  readonly pubkey: string;
  readonly method: LoginMethod;
  readonly capabilities: SignerCapabilities;
  /** Version 1 gates each sign/NIP-04/NIP-44 provider start, including retries
   * and deferred upgrades. It does not fence transport-internal wire frames,
   * initial connection/login or the separate NIP-46 management methods. */
  readonly providerEffectBoundary?: 1;
  signEvent(template: EventTemplate, boundary?: SignerEffectBoundary): Promise<NostrEvent>;
  nip04?: {
    encrypt(peerPubkey: string, plaintext: string, boundary?: SignerEffectBoundary): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string, boundary?: SignerEffectBoundary): Promise<string>;
  };
  nip44?: {
    encrypt(peerPubkey: string, plaintext: string, boundary?: SignerEffectBoundary): Promise<string>;
    decrypt(peerPubkey: string, ciphertext: string, boundary?: SignerEffectBoundary): Promise<string>;
  };
  nip46?: {
    /** Optional receive-only transport boundary. No account-signing or
     * message-encryption authority is exposed, and it never falls back to an
     * unguarded backend. Already-sent RPCs cannot be retracted. */
    decryptNip44Guarded?(peerPubkey: string, ciphertext: string, boundary: Nip46DecryptBoundary): Promise<string>;
    ping(): Promise<void>;
    switchRelays(): Promise<boolean>;
    logout(): Promise<void>;
    /**
     * Ask a supporting bunker to provision its literal Vennel `rendezvous`
     * child to this NIP-46 client's public key. The returned value is an
     * opaque, signer-encrypted response; it never contains a raw child key.
     * Unsupported signers reject the request rather than falling back to a
     * generic derivation or an identity-key crypto operation.
     */
    provisionRendezvous(index: number, nonce: Uint8Array, expiresAt: number): Promise<string>;
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

export type NostrConnectStatusType =
  | 'uri-created'
  | 'relay-connecting'
  | 'relay-connected'
  | 'signer-seen'
  | 'request-sent'
  | 'response-received'
  | 'auth-url'
  | 'timeout'
  | 'error';

export type NostrConnectStatusPhase =
  | 'pairing'
  | 'relay'
  | 'subscription'
  | 'request'
  | 'publish'
  | 'response'
  | 'abort';

export interface NostrConnectStatus {
  type: NostrConnectStatusType;
  timestamp: number;
  relays: string[];
  clientPubkey?: string;
  signerPubkey?: string;
  relay?: string;
  uri?: string;
  method?: string;
  requestId?: string;
  timeoutMs?: number;
  /** For `auth-url`: the page the signer asked the user to open. */
  authUrl?: string;
  phase?: NostrConnectStatusPhase;
  message?: string;
  error?: unknown;
}

export type NostrConnectStatusHandler = (status: NostrConnectStatus) => void;

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
 * Only affects the Local Signet picker path (`local-signet`, legacy
 * `redirect`). NIP-07 and bunker are unchanged.
 */
export type SignetDeliveryMode = 'relay' | 'redirect';

/** Key-value storage backend used for Signet Access session persistence. */
export interface SignetStorage {
  /** Opt in to required custody: backend rejection propagates to the caller
   * instead of becoming an absent read or a successful skipped write.
   * Keep this policy fixed for the backend's lifetime. The backend owns
   * concurrency, atomic snapshots, corruption checks and unknown receipts. */
  readonly required?: boolean;
  /** Required mode session reads must return one coherent snapshot containing
   * exactly every requested key (null means authenticated absence). */
  getItems?(keys: readonly string[]): Readonly<Record<string, string | null>> | Promise<Readonly<Record<string, string | null>>>;
  /** Required session replacement/deletion atomically compares every expected
   * key before committing all changes. null means absence/removal. Return true
   * only after acknowledgement, false on a definite mismatch; unknown commits
   * remain pending until the backend has reconciled them. */
  setItems?(changes: Readonly<Record<string, string | null>>, expected: Readonly<Record<string, string | null>>): boolean | Promise<boolean>;
  /** Required first-use and pending custody: atomically replace exactly the
   * expected value (null means absence). Resolve true only after the change
   * acknowledges, false on a known mismatch. Unknown commits remain pending. */
  compareAndSetItem?(key: string, expected: string | null, value: string | null): boolean | Promise<boolean>;
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** Options for Signet.login(). */
export interface LoginOptions {
  /** Required. Shown in the consent UI (e.g. "Asteroid Sats"). */
  appName: string;
  /** Optional 64-hex challenge. Auto-generated if omitted. */
  challenge?: string;
  /**
   * Skip the picker and force a specific method. `local-signet` opens Signet on
   * this device; `remote-signet` shows a cross-device Signet QR. Legacy aliases
   * `redirect` and `qr` still work for those two Signet paths.
   */
  preferredMethod?: LoginPickerMethod;
  /**
   * Picker methods to show, in order. Unavailable methods such as NIP-07 when
   * no extension is installed are hidden at render time. Default shows every
   * supported method, with power-user paths grouped under Advanced.
   */
  methods?: LoginPickerMethod[];
  /**
   * Subset of `methods` grouped behind Advanced. Pass `[]` to show all allowed
   * methods in the main picker. Default: bunker, nostrconnect, nsec.
   */
  advancedMethods?: LoginPickerMethod[];
  /** Relay URL for cross-device communication. Default wss://nos.lol — must serve kind-1059 gift wraps to an unauthenticated reader. */
  relayUrl?: string;
  /**
   * Relay URLs for NIP-46 / NostrConnect. Use `relayUrl` separately when the
   * Signet QR/relay delivery path should stay on a different primary relay.
   * The Signet QR/redirect link also names these (after `relayUrl`, deduplicated,
   * at most 3 in all) and listens on all of them.
   */
  relayUrls?: string[];
  /**
   * Permissions requested by the app-initiated NostrConnect flow.
   * Default: sign_event, nip44_encrypt, nip44_decrypt.
   */
  nostrConnectPerms?: string[];
  /**
   * Receives detailed app-initiated NostrConnect progress events. Use this for
   * diagnostics, custom UI, and telemetry instead of scraping the built-in
   * modal text.
   */
  onNostrConnectStatus?: NostrConnectStatusHandler;
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
   * 'redirect', not by the default Local Signet relay flow.
   */
  redirectCallback?: string;
  /**
   * Delivery mode for the Sign in with Signet method. See `SignetDeliveryMode`.
   * Default: 'relay'.
   *
   * In 'redirect' mode `Signet.login()` navigates the current tab away. In the
   * normal handoff the returned promise is abandoned; if the user backs out and
   * the browser restores the original page, it resolves null. Wire up
   * `Signet.handleCallback()` on boot to receive the session on return.
   */
  mode?: SignetDeliveryMode;
  /**
   * Storage backend for sessions, pending redirects, and the persistent NIP-46
   * client key. Defaults to localStorage. Use this for encrypted, async,
   * server-backed, or test storage.
   */
  storage?: SignetStorage;
  /** Persist the session. Default: true. */
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

/**
 * A cross-device (relay) sign-in in flight, persisted so it survives the page
 * being discarded while the user is in the signer app.
 *
 * The redirect flow has always persisted its anchor (`PendingRedirect`); the
 * relay flow did not, so a discarded tab lost the ephemeral session key and the
 * response — already published, addressed to that key — became unreachable.
 */
export interface PendingRelayAuth {
  /** 64-hex challenge issued at login start — also the `requestId`. */
  challenge: string;
  /** Origin that initiated the login — must match on resume. */
  origin: string;
  /** App name, for the resumed UI. */
  appName: string;
  /** The primary `wss://` relay the request was published to. */
  relayUrl: string;
  /**
   * Every relay the auth link named, primary first (at most 3). Absent on
   * records written before multi-relay links; treat those as `[relayUrl]`.
   */
  relayUrls?: string[];
  /**
   * The ephemeral session private key, hex.
   *
   * Deliberately persisted: resuming after page discard is impossible without
   * it. It signs nothing and carries no identity — its only power is unwrapping
   * one auth response addressed to it, and that power dies with the 300-second
   * freshness window. Cleared on settle, on expiry and on logout.
   */
  sessionSkHex: string;
  /**
   * Unix **seconds** when the sign-in was issued — the anchor. Note this is
   * seconds, matching `signet-verify`'s `issuedAt`, where
   * `PendingRedirect.createdAt` is milliseconds.
   */
  issuedAt: number;
}

/** Options for Signet.restoreSession(). */
export interface RestoreOptions {
  /** Reconnect a stored bunker session if present. Default: true. */
  reconnectBunker?: boolean;
  /** Default relay for bunker reconnection if URI omits it. */
  defaultRelay?: string;
  /** Receives detailed NIP-46 reconnect progress events for stored bunker sessions. */
  onNostrConnectStatus?: NostrConnectStatusHandler;
  /**
   * Storage backend for session restore. Must match the backend passed to
   * `login()` / `handleRedirectCallback()` if you override the default.
   */
  storage?: SignetStorage;
}

/** Default values applied when the consumer omits an option. */
export const DEFAULTS = {
  // The Signet app's own relay. relay.damus.io was the default until it began
  // refusing kind-1059 (gift wrap) reads to unauthenticated clients, with its
  // AUTH misconfigured so that no client can fetch one — every cross-device
  // sign-in on the default then failed. It still serves NIP-46 (kind 24133).
  relayUrl: DEFAULT_RELAY_URL,
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
export const PENDING_REDIRECT_TTL_MS = AUTH_FRESHNESS_WINDOW_SEC * 1000;

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
  /** A cross-device sign-in in flight — see `PendingRelayAuth`. */
  pendingRelayAuth: 'signet:login.pendingRelayAuth',
};
