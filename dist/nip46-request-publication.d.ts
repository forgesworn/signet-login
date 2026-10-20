import type { NostrEvent } from './types.js';
/** Publish one already-signed decrypt request. This owns only its EVENT
 * sockets, never the shared response subscription or signer connection.
 * No queue, reconnect or retry may outlive this request's permission. */
export declare function publishNip46DecryptRequest(event: NostrEvent, relays: readonly string[], current: () => boolean, timeoutMs: number, Base: typeof WebSocket): Promise<void>;
