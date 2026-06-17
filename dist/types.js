/**
 * Public types for signet-login.
 *
 * The SDK exposes a single SignetSigner interface across extension, Signet,
 * NIP-46, Android, and local fallback paths. Consumers code against the
 * interface; the SDK picks the implementation based on user choice.
 */
/** Default values applied when the consumer omits an option. */
export const DEFAULTS = {
    relayUrl: 'wss://relay.damus.io',
    signetAppOrigin: 'https://mysignet.app',
    timeout: 120000,
    theme: 'auto',
    persist: true,
    mode: 'relay',
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
