/**
 * Three signer implementations behind one interface.
 *
 *   Nip07Signer       — wraps window.nostr (bark, Alby, nos2x, Flamingo, …)
 *   BunkerSignerImpl  — wraps nostr-tools BunkerSigner (NIP-46 over relay)
 *   EphemeralSigner   — auth-only fallback when only the redirect signature is available
 */
import type { EventTemplate, NostrConnectStatusHandler, NostrEvent, SignetAuthEvent, SignetSigner, SignerCapabilities } from './types.js';
/** The shape of `window.nostr` exposed by NIP-07 extensions. */
interface Nip07Provider {
    getPublicKey(): Promise<string>;
    signEvent(event: EventTemplate): Promise<NostrEvent>;
    nip04?: {
        encrypt(peerPubkey: string, plaintext: string): Promise<string>;
        decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
    };
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
export declare function hasNip07(): boolean;
export declare class Nip07Signer implements SignetSigner {
    readonly pubkey: string;
    private readonly provider;
    readonly method: "nip07";
    readonly capabilities: SignerCapabilities;
    readonly nip04?: SignetSigner['nip04'];
    readonly nip44?: SignetSigner['nip44'];
    constructor(pubkey: string, provider: Nip07Provider);
    signEvent(template: EventTemplate): Promise<NostrEvent>;
    close(): Promise<void>;
}
/** Connects to the page's NIP-07 provider and returns a Nip07Signer. */
export declare function createNip07Signer(): Promise<Nip07Signer>;
interface Nip46SignerClient {
    getPublicKey(): Promise<string>;
    signEvent(event: EventTemplate): Promise<NostrEvent>;
    nip04Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    nip04Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
    nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
    nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
    ping(): Promise<void>;
    switchRelays(): Promise<boolean>;
    logout(): Promise<void>;
    close(): Promise<void>;
}
/** Wraps a NIP-46 client with our SignetSigner interface. */
export declare class BunkerSignerImpl implements SignetSigner {
    readonly pubkey: string;
    private readonly bunker;
    /** Original bunker URI — kept for persistence/reconnect. */
    readonly bunkerUri: string;
    /** The 32-byte client secret key used in this session — kept for reconnect. */
    readonly clientSecretKey: Uint8Array;
    readonly method: "bunker";
    readonly capabilities: SignerCapabilities;
    readonly nip04: SignetSigner['nip04'];
    readonly nip44: SignetSigner['nip44'];
    readonly nip46: SignetSigner['nip46'];
    constructor(pubkey: string, bunker: Nip46SignerClient, 
    /** Original bunker URI — kept for persistence/reconnect. */
    bunkerUri: string, 
    /** The 32-byte client secret key used in this session — kept for reconnect. */
    clientSecretKey: Uint8Array);
    signEvent(template: EventTemplate): Promise<NostrEvent>;
    close(): Promise<void>;
}
/**
 * App-initiated NIP-46: we generate a `nostrconnect://` URI containing our
 * client pubkey, relay, secret, and requested perms. The user pastes/scans
 * it into their signer, which then connects to the relay and acks. Returns
 * a BunkerSignerImpl once the handshake completes (or rejects on abort).
 *
 *   uri              — the nostrconnect:// URI shown to the user (built by
 *                      the caller via buildNostrConnectUri)
 *   clientSecretKey  — the 32-byte session key the URI was built with
 *   abortSignal      — cancel a long-running wait when the modal closes
 *   timeoutMs        — pairing wait deadline; defaults to 5 minutes
 *   onStatus         — detailed pairing and NIP-46 request progress events
 */
export declare function createBunkerSignerFromNostrConnect(input: {
    uri: string;
    clientSecretKey: Uint8Array;
    abortSignal?: AbortSignal;
    timeoutMs?: number;
    onStatus?: NostrConnectStatusHandler;
}): Promise<BunkerSignerImpl>;
/**
 * Build a NIP-46 `nostrconnect://` URI for the app-initiated flow. The
 * `secret` is echoed back by the bunker on connect so the app can verify
 * it's talking to the right peer; it must be unguessable.
 */
export declare function buildNostrConnectUri(input: {
    clientPubkeyHex: string;
    relayUrl?: string;
    relayUrls?: string[];
    secret: string;
    perms?: string[];
    appName?: string;
    appUrl?: string;
}): string;
/**
 * Convert an app-generated `nostrconnect://` pairing URI into the equivalent
 * signer-published `bunker://` reconnect URI once the signer pubkey is known.
 *
 * `nostrconnect://` is a one-time app-to-signer invitation; it only contains
 * the client pubkey. After the signer responds, future restores should use
 * `bunker://signerPubkey?...` with the same relays and secret.
 */
export declare function buildBunkerUriFromNostrConnectUri(nostrConnectUri: string, signerPubkeyHex: string): string;
export declare function isBunkerUri(value: string): boolean;
export declare function isNostrConnectUri(value: string): boolean;
export declare function isSupportedPairingUri(value: string): boolean;
/**
 * Connect a bunker session from a `bunker://` URI or NIP-05 identifier. Pass
 * `clientSecretKey` to bind a stable client pubkey the signer can auto-approve
 * (see `loadOrCreatePersistentClientSk`); when omitted a fresh ephemeral key is
 * generated, which a per-pubkey-approving bunker will treat as a new,
 * unapproved client.
 */
export declare function createBunkerSigner(input: {
    uri: string;
    clientSecretKey?: Uint8Array;
    onauth?: (url: string) => void;
    onStatus?: NostrConnectStatusHandler;
    /**
     * Bound the NIP-46 `connect` + `get_public_key` handshake, in milliseconds.
     * Omit for the interactive paste flow, where a cold remote signer may
     * legitimately take tens of seconds to approve via the `auth_url` callback.
     * Set it for unattended boot-time connects (redirect-bunker auto-pair,
     * session restore) where a non-responding signer must degrade to the
     * auth-only fallback rather than stall. On expiry the half-open signer is
     * closed and the call rejects with `bunker-connect-timeout`.
     */
    timeoutMs?: number;
}): Promise<BunkerSignerImpl>;
/** Generate a 32-byte secret key. */
export declare function generateSecretKey(): Uint8Array;
/**
 * Holds a 32-byte private key in memory, signs locally with schnorr, exposes
 * NIP-44 via nostr-tools. The key is never persisted by this signer — the SDK
 * will not call any storage write for an nsec session, so reloads land back
 * on the picker. The consumer must surface the security trade-off in the UI.
 */
export declare class LocalSigner implements SignetSigner {
    readonly pubkey: string;
    private readonly privkey;
    readonly method: "nsec";
    readonly capabilities: SignerCapabilities;
    readonly nip04: SignetSigner['nip04'];
    readonly nip44: SignetSigner['nip44'];
    constructor(pubkey: string, privkey: Uint8Array);
    signEvent(template: EventTemplate): Promise<NostrEvent>;
    close(): Promise<void>;
}
/**
 * Decode a bech32 nsec into a LocalSigner. Accepts either the `nsec1...`
 * prefix or a raw 64-char hex private key for power-user paste paths.
 * Throws on any malformed input — caller surfaces the error to the user.
 */
export declare function createLocalSignerFromNsec(input: string): LocalSigner;
/**
 * Auth-only signer returned by the redirect/QR flow before Option B is built.
 * Holds the signed challenge but cannot sign further events.
 */
export declare class EphemeralSigner implements SignetSigner {
    readonly pubkey: string;
    readonly authEvent: SignetAuthEvent;
    readonly method: "redirect";
    readonly capabilities: SignerCapabilities;
    constructor(pubkey: string, authEvent: SignetAuthEvent);
    signEvent(_template: EventTemplate): Promise<NostrEvent>;
    close(): Promise<void>;
}
/**
 * A redirect-bunker signer whose bunker connects in the BACKGROUND.
 *
 * `handleRedirectCallback` returns this immediately so the consumer can paint a
 * signed-in UI without waiting on an up-to-8s bunker handshake over flaky
 * relays (the cause of the "blank screen on sign-in"). The authenticated pubkey
 * is known up front; the first `signEvent` / `nip44` call awaits the background
 * connect. If that connect fails, signing rejects with the auth-only error —
 * the session is still valid for identity proof.
 */
export declare class DeferredBunkerSigner implements SignetSigner {
    readonly pubkey: string;
    readonly authEvent: SignetAuthEvent;
    /** Resolves to the connected bunker, or null if the connect failed. */
    private readonly upgrade;
    /** Original bunker URI — exposed so persistence can reconnect on reload. */
    readonly bunkerUri?: string | undefined;
    /** Stable client key — exposed so persistence keeps the same NIP-46 client pubkey. */
    readonly clientSecretKey?: Uint8Array | undefined;
    readonly method: "bunker";
    readonly capabilities: SignerCapabilities;
    readonly nip04: SignetSigner['nip04'];
    readonly nip44: SignetSigner['nip44'];
    readonly nip46: SignetSigner['nip46'];
    constructor(pubkey: string, authEvent: SignetAuthEvent, 
    /** Resolves to the connected bunker, or null if the connect failed. */
    upgrade: Promise<BunkerSignerImpl | null>, 
    /** Original bunker URI — exposed so persistence can reconnect on reload. */
    bunkerUri?: string | undefined, 
    /** Stable client key — exposed so persistence keeps the same NIP-46 client pubkey. */
    clientSecretKey?: Uint8Array | undefined, optimisticCapabilities?: boolean);
    private live;
    signEvent(template: EventTemplate): Promise<NostrEvent>;
    close(): Promise<void>;
}
export {};
