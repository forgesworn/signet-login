import type { SignerEffectBoundary } from './types.js';
/** The boundary owns the decision to start, not the provider or its keys.
 * Each callback starts at most once and cannot be retained past settlement.
 * A boundary failure after start still joins the unabortable provider. */
export declare function withProviderEffect<T>(boundary: SignerEffectBoundary | undefined, work: () => Promise<T>): Promise<T>;
