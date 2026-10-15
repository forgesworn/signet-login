import type { SignerEffectBoundary } from './types.js';

/** The boundary owns the decision to start, not the provider or its keys.
 * Each callback starts at most once and cannot be retained past settlement.
 * A boundary failure after start still joins the unabortable provider. */
export function withProviderEffect<T>(boundary: SignerEffectBoundary | undefined, work: () => Promise<T>): Promise<T> {
  if (boundary === undefined) return work();
  return (async () => {
    const start = boundary.start;
    if (typeof start !== 'function') throw new Error('invalid-signer-effect-boundary');
    let called = false, settled = false, provider: Promise<T> | undefined;
    const once = () => {
      if (called || settled) throw new Error('signer-effect-already-started-or-settled');
      called = true;
      try { provider = Promise.resolve(work()); }
      catch (error) { provider = Promise.reject(error); }
      void provider.catch(() => {});
      return provider;
    };
    try {
      const value = await start.call(boundary, once);
      if (!called || !provider) throw new Error('signer-effect-not-started');
      const provided = await provider;
      if (value !== provided) throw new Error('signer-effect-result-substituted');
      return provided;
    } finally {
      settled = true;
      if (provider) await provider.catch(() => {});
    }
  })();
}
