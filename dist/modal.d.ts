/**
 * The login modal — picker → method-specific UI → resolved session.
 *
 * Mirrors signet-verify's <dialog>-based pattern: native focus trap,
 * top-layer placement, theme-aware colours, no third-party UI deps.
 */
import type { LoginOptions, SignetSession } from './types.js';
/**
 * Entry point — show the modal, route to the chosen method, return a session.
 *
 * Returns null when the user cancels or the flow times out.
 */
export declare function showLoginModal(opts: LoginOptions): Promise<SignetSession | null>;
