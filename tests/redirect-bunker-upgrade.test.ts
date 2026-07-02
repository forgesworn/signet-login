/**
 * Regression test for the background redirect-bunker upgrade path in
 * `handleRedirectCallback` (src/signet-login.ts). When signet-app hands back
 * a `bunker://` URI on a redirect callback, the SDK connects to it in the
 * BACKGROUND (not awaited by the caller) and, on success, re-persists the
 * session with `void persistSession(liveSession, options.storage)`. Unlike
 * its sibling calls, that one had no `.catch()` — if persistence ever threw,
 * it would surface as an unhandled promise rejection with nothing awaiting
 * the background upgrade chain.
 *
 * `saveSessionToStorage` is mocked directly (bypassing the storage layer's
 * own best-effort try/catch around individual `setItem` calls) so this test
 * exercises a rejection at the exact call site the fix targets.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/storage.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/storage.js')>();
  return {
    ...actual,
    saveSessionToStorage: vi.fn(actual.saveSessionToStorage),
  };
});

vi.mock('../src/signers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/signers.js')>();
  return {
    ...actual,
    createBunkerSigner: vi.fn(),
  };
});

import { saveSessionToStorage, savePendingRedirect } from '../src/storage.js';
import { createBunkerSigner } from '../src/signers.js';
import { handleRedirectCallback } from '../src/signet-login.js';
import { callbackSearchForAuthEvent, makeAuthEvent } from './helpers/auth-event.js';

const ORIGIN_JSDOM = window.location.origin;
const APP_NAME = 'Pallasite';
const CHALLENGE = 'a'.repeat(64);

function setLocation(search: string): void {
  const fullSearch = search.startsWith('?') ? search : (search ? `?${search}` : '');
  window.history.replaceState(null, '', `/${fullSearch}`);
}

async function settleMicrotasks(rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}

/** Yield to a real macrotask so Node's unhandledRejection detection can fire. */
async function yieldToMacrotask(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0));
}

describe('redirect-bunker background upgrade persistence', () => {
  beforeEach(() => {
    localStorage.clear();
    setLocation('');
    vi.mocked(createBunkerSigner).mockReset();
    vi.mocked(saveSessionToStorage).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not produce an unhandled rejection when the background bunker-upgrade persist fails', async () => {
    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown): void => { unhandled.push(reason); };
    process.on('unhandledRejection', onUnhandledRejection);

    try {
      const t = Math.floor(Date.now() / 1000);
      const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: ORIGIN_JSDOM, createdAt: t });
      savePendingRedirect({
        challenge: CHALLENGE,
        origin: ORIGIN_JSDOM,
        appName: APP_NAME,
        createdAt: Date.now(),
      });

      const bunkerUri = `bunker://${authEvent.pubkey}?relay=wss%3A%2F%2Frelay.example`;
      const fakeBunkerSigner = {
        pubkey: authEvent.pubkey,
        method: 'bunker' as const,
        capabilities: { canSignEvents: true, hasNip44: true },
        bunkerUri,
        clientSecretKey: new Uint8Array(32).fill(3),
        close: vi.fn(async () => {}),
        signEvent: vi.fn(),
      };
      vi.mocked(createBunkerSigner).mockResolvedValue(fakeBunkerSigner as unknown as Awaited<ReturnType<typeof createBunkerSigner>>);

      // First saveSessionToStorage call is the synchronous "deferred session"
      // persist (awaited by handleRedirectCallback — must succeed so the
      // callback itself resolves). The second is the background upgrade's
      // re-persist with live bunker creds — this is the one under test.
      let saveCalls = 0;
      vi.mocked(saveSessionToStorage).mockImplementation(async () => {
        saveCalls += 1;
        if (saveCalls === 2) throw new Error('storage-write-failed');
      });

      setLocation(callbackSearchForAuthEvent(authEvent, { bunker: bunkerUri }));

      const result = await handleRedirectCallback();
      expect(result.kind).toBe('session');

      // Let the background upgrade (createBunkerSigner's mocked resolution,
      // then its `.then()` handler including the persistSession re-write)
      // run to completion.
      await settleMicrotasks();
      await yieldToMacrotask();
      await settleMicrotasks();

      expect(saveCalls).toBe(2);
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandledRejection);
    }
  });
});
