/**
 * The relay-delivered Signet flows (`remote-signet` / `local-signet`) are the
 * only login paths whose proof arrives from outside this package —
 * `signet-verify`'s `waitForAuthResponse`. Every other path runs the returned
 * event through `assertValidLoginAuthEvent` before building a session; these
 * tests pin that the relay path does too, so a bad or mismatched proof cannot
 * become a session on the strength of the upstream check alone.
 *
 * The `expectedPubkey` binding matters most: the session's `pubkey` comes from
 * `result.pubkey` while the consumer's server verifies `authEvent`, so nothing
 * else stops those two identities from disagreeing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Only the network wait is faked; every constant comes from the real package,
// so a test of a signet-login default checks the value it actually ships with.
vi.mock('signet-verify', async importOriginal => ({
  ...(await importOriginal<typeof import('signet-verify')>()),
  waitForAuthResponse: vi.fn(() => new Promise(() => { /* overridden per test */ })),
}));

import { bytesToHex } from '@noble/hashes/utils';
import { waitForAuthResponse } from 'signet-verify';
import { login } from '../src/signet-login.js';
import { loadPendingRelayAuth, savePendingRelayAuth } from '../src/storage.js';
import type { PendingRelayAuth } from '../src/types.js';
import { makeAuthEvent, TEST_PRIVATE_KEY } from './helpers/auth-event.js';

/** A request object shaped like what the modal passes to waitForAuthResponse. */
interface CapturedWaitRequest {
  requestId: string;
  relayUrl: string;
  sessionPrivKey: Uint8Array;
  issuedAt?: number;
  timeout?: number;
  abortSignal?: AbortSignal;
}

function lastWaitCall(): CapturedWaitRequest {
  const call = vi.mocked(waitForAuthResponse).mock.calls.at(-1);
  if (!call) throw new Error('waitForAuthResponse was never called');
  return call[0] as unknown as CapturedWaitRequest;
}

function neverSettle(): void {
  vi.mocked(waitForAuthResponse).mockImplementation(() => new Promise(() => { /* left pending */ }));
}

function codedError(code: string): Error & { code: string } {
  const err = new Error(code) as Error & { code: string };
  err.code = code;
  return err;
}

function makePersistedRecord(overrides: Partial<PendingRelayAuth> = {}): PendingRelayAuth {
  return {
    challenge: 'd'.repeat(64),
    origin: window.location.origin,
    appName: 'Pallasite',
    relayUrl: 'wss://relay.example',
    sessionSkHex: 'e'.repeat(64),
    issuedAt: Math.floor(Date.now() / 1000) - 30,
    ...overrides,
  };
}

const CHALLENGE = 'b'.repeat(64);

function installDialogPolyfill(): void {
  if (typeof HTMLDialogElement.prototype.showModal !== 'function') {
    HTMLDialogElement.prototype.showModal = function showModal() {
      this.setAttribute('open', '');
    };
  }
  if (typeof HTMLDialogElement.prototype.close !== 'function') {
    HTMLDialogElement.prototype.close = function close() {
      this.removeAttribute('open');
    };
  }
}

async function settleMicrotasks(rounds = 8): Promise<void> {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}

function startRelayLogin(): Promise<unknown> {
  return login({
    appName: 'Pallasite',
    challenge: CHALLENGE,
    theme: 'dark', // jsdom has no matchMedia; 'auto' would need one
    preferredMethod: 'remote-signet',
    relayUrl: 'wss://relay.example',
    persist: false,
  });
}

function statusText(): string {
  return document.getElementById('signet-login-status')?.textContent ?? '';
}

/**
 * A refused proof deliberately leaves the modal open so the user can retry or
 * back out, which means the login promise is still pending. `showLoginModal`
 * serialises on a module-level queue, so a test that walked away from one
 * would wedge every later test behind it. Dismiss it the way a user would.
 */
async function cancelAndDrain(pending: Promise<unknown>): Promise<void> {
  document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
  await expect(pending).resolves.toBeNull();
}

describe('relay login path verifies the auth event locally', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('builds a session from a well-formed proof', async () => {
    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: window.location.origin });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: authEvent.pubkey,
      authEvent,
    } as never);

    const session = await startRelayLogin() as { pubkey: string; method: string };
    expect(session.pubkey).toBe(authEvent.pubkey);
    expect(session.method).toBe('redirect');
  });

  it('refuses a proof whose pubkey differs from the reported session pubkey', async () => {
    // A relay result that authenticates one key while naming another would
    // leave the browser session and the server-verified identity disagreeing.
    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: window.location.origin });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: 'f'.repeat(64),
      authEvent,
    } as never);

    const pending = startRelayLogin();
    let settled = false;
    void pending.then(() => { settled = true; });
    await settleMicrotasks();

    expect(settled).toBe(false);
    expect(statusText()).toContain('auth-event-invalid:pubkey-mismatch');
    await cancelAndDrain(pending);
  });

  it('refuses a proof carrying the wrong challenge', async () => {
    const authEvent = makeAuthEvent({ challenge: 'c'.repeat(64), origin: window.location.origin });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: authEvent.pubkey,
      authEvent,
    } as never);

    const pending = startRelayLogin();
    let settled = false;
    void pending.then(() => { settled = true; });
    await settleMicrotasks();

    expect(settled).toBe(false);
    expect(statusText()).toContain('auth-event-invalid:challenge-mismatch');
    await cancelAndDrain(pending);
  });

  it('refuses a proof bound to a different origin', async () => {
    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: 'https://attacker.example' });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: authEvent.pubkey,
      authEvent,
    } as never);

    const pending = startRelayLogin();
    let settled = false;
    void pending.then(() => { settled = true; });
    await settleMicrotasks();

    expect(settled).toBe(false);
    expect(statusText()).toContain('auth-event-invalid:origin-mismatch');
    await cancelAndDrain(pending);
  });

  it('refuses a proof with a tampered signature', async () => {
    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: window.location.origin });
    const forged = { ...authEvent, sig: authEvent.sig.replace(/^.{2}/, '00') };
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: forged.pubkey,
      authEvent: forged,
    } as never);

    const pending = startRelayLogin();
    let settled = false;
    void pending.then(() => { settled = true; });
    await settleMicrotasks();

    expect(settled).toBe(false);
    expect(statusText()).toContain('auth-event-invalid:invalid-signature');
    await cancelAndDrain(pending);
  });

  it('accepts a proof that carries extra signed tags', async () => {
    // signet-app appends avatar metadata to the event it signs; the local
    // check must not be stricter than the tag set the signer actually uses.
    const authEvent = makeAuthEvent({
      challenge: CHALLENGE,
      origin: window.location.origin,
      privKey: TEST_PRIVATE_KEY,
      extraTags: [['avatar_hash', 'a'.repeat(64)]],
    });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: authEvent.pubkey,
      authEvent,
    } as never);

    const session = await startRelayLogin() as { pubkey: string };
    expect(session.pubkey).toBe(authEvent.pubkey);
  });
});

describe('resuming a persisted cross-device sign-in', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    neverSettle();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('resumes a live record when the consumer supplies no challenge of its own', async () => {
    const persisted = makePersistedRecord();
    await savePendingRelayAuth(persisted);

    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'remote-signet',
      relayUrl: persisted.relayUrl,
      persist: false,
    });
    await settleMicrotasks();

    const call = lastWaitCall();
    expect(call.requestId).toBe(persisted.challenge);
    expect(call.issuedAt).toBe(persisted.issuedAt);
    expect(bytesToHex(call.sessionPrivKey)).toBe(persisted.sessionSkHex);

    const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement;
    const url = new URL(link.href);
    expect(url.searchParams.get('t')).toBe(String(persisted.issuedAt));
    expect(url.searchParams.get('challenge')).toBe(persisted.challenge);

    await cancelAndDrain(pending);
  });

  it('starts a fresh sign-in when the consumer passes a challenge that does not match a live record', async () => {
    const persisted = makePersistedRecord();
    await savePendingRelayAuth(persisted);
    const freshChallenge = 'f'.repeat(64);

    const pending = login({
      appName: 'Pallasite',
      challenge: freshChallenge,
      theme: 'dark',
      preferredMethod: 'remote-signet',
      relayUrl: persisted.relayUrl,
      persist: false,
    });
    await settleMicrotasks();

    const call = lastWaitCall();
    expect(call.requestId).toBe(freshChallenge);
    expect(call.issuedAt).not.toBe(persisted.issuedAt);
    expect(bytesToHex(call.sessionPrivKey)).not.toBe(persisted.sessionSkHex);

    await cancelAndDrain(pending);
  });

  it('stamps a fresh issuedAt matching the auth URL t= when there is no persisted record', async () => {
    const before = Math.floor(Date.now() / 1000);

    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'remote-signet',
      relayUrl: 'wss://relay.example',
      persist: false,
    });
    await settleMicrotasks();

    const call = lastWaitCall();
    expect(call.issuedAt).toBeGreaterThanOrEqual(before);

    const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement;
    const url = new URL(link.href);
    expect(url.searchParams.get('t')).toBe(String(call.issuedAt));

    await cancelAndDrain(pending);
  });
});

describe('explicit vs defaulted timeout on the relay wait', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    neverSettle();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('passes timeout: undefined — never the 120s default — when the consumer sets no timeout', async () => {
    // resolveOptions always fills ResolvedOptions.timeout with the 120s
    // default. If the relay wait were given THAT, it would silently override
    // signet-verify's deadline-derived default and restore the flat 120s
    // give-up this work removes. Only `explicitTimeout` — set only when the
    // consumer actually passed one — may reach the wait.
    const pending = login({
      appName: 'Pallasite',
      challenge: CHALLENGE,
      theme: 'dark',
      preferredMethod: 'remote-signet',
      relayUrl: 'wss://relay.example',
      persist: false,
    });
    await settleMicrotasks();

    const call = lastWaitCall();
    expect(call.timeout).toBeUndefined();
    expect(Number.isFinite(call.issuedAt)).toBe(true);

    await cancelAndDrain(pending);
  });

  it('passes the consumer-supplied timeout through unchanged', async () => {
    const pending = login({
      appName: 'Pallasite',
      challenge: CHALLENGE,
      theme: 'dark',
      preferredMethod: 'remote-signet',
      relayUrl: 'wss://relay.example',
      timeout: 30_000,
      persist: false,
    });
    await settleMicrotasks();

    const call = lastWaitCall();
    expect(call.timeout).toBe(30_000);

    await cancelAndDrain(pending);
  });
});

describe('clearing the persisted record on terminal outcomes', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('clears the record on a successful sign-in — the persisted key has no further use', async () => {
    const authEvent = makeAuthEvent({ challenge: CHALLENGE, origin: window.location.origin });
    vi.mocked(waitForAuthResponse).mockResolvedValue({
      pubkey: authEvent.pubkey,
      authEvent,
    } as never);

    await startRelayLogin();
    expect(await loadPendingRelayAuth()).toBeNull();
  });

  it.each(['expired', 'denied', 'aborted'])(
    'clears the record on %s — this sign-in is over and cannot be resumed',
    async code => {
      vi.mocked(waitForAuthResponse).mockRejectedValue(codedError(code));

      const pending = startRelayLogin();
      await settleMicrotasks();
      expect(await loadPendingRelayAuth()).toBeNull();

      await cancelAndDrain(pending);
    },
  );

  it.each(['timeout', 'relay-error', 'relay-closed'])(
    'keeps the record on %s — a retry against the same issuedAt can still work',
    async code => {
      vi.mocked(waitForAuthResponse).mockRejectedValue(codedError(code));

      const pending = startRelayLogin();
      await settleMicrotasks();
      const record = await loadPendingRelayAuth();
      expect(record).not.toBeNull();
      expect(record?.challenge).toBe(CHALLENGE);

      await cancelAndDrain(pending);
    },
  );
});

describe('aborting the relay wait on Back/Cancel', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    neverSettle();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('closes the relay subscription (fires the abortSignal) when Cancel is clicked', async () => {
    const pending = startRelayLogin();
    await settleMicrotasks();

    const { abortSignal } = lastWaitCall();
    expect(abortSignal).toBeInstanceOf(AbortSignal);
    expect(abortSignal?.aborted).toBe(false);

    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();

    expect(abortSignal?.aborted).toBe(true);
  });

  it('closes the relay subscription when Back is clicked', async () => {
    const pending = startRelayLogin();
    await settleMicrotasks();

    const { abortSignal } = lastWaitCall();

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();

    expect(abortSignal?.aborted).toBe(true);
  });

  it.each(['cancel', 'back'])(
    'clears the persisted record on %s — resume survives the OS, never the user',
    async action => {
      // A deliberate exit must not leave the request behind: the next phone
      // sign-in would silently resume it, trapping someone who cancelled to get
      // a fresh QR inside a request with seconds left. Settle marks the flow
      // settled before the abort's rejection arrives, so the rejection handler
      // never sees it — clearing has to happen on the exit itself.
      const pending = startRelayLogin();
      await settleMicrotasks();
      expect(await loadPendingRelayAuth()).not.toBeNull();

      document.querySelector<HTMLButtonElement>(`[data-action="${action}"]`)?.click();
      await expect(pending).resolves.toBeNull();
      await settleMicrotasks();

      expect(await loadPendingRelayAuth()).toBeNull();
    },
  );
});

describe('rendering the countdown and named expiry state', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('renders the deadline anchored to issuedAt instead of an open-ended spinner', async () => {
    neverSettle();
    const pending = startRelayLogin();
    await settleMicrotasks();

    const countdown = document.getElementById('signet-login-countdown');
    // issuedAt is stamped moments before this assertion runs, so the full 5:00
    // window may have ticked to 4:59 by the time we read it.
    expect(countdown?.textContent).toMatch(/^Approve on your phone · [45]:\d\d remaining$/);

    await cancelAndDrain(pending);
  });

  it('ticks down anchored to issuedAt rather than resetting on each render', async () => {
    // Full fake timers (Date included) — advancing the clock must actually
    // move remainingSeconds, not just fire the interval callback on a frozen
    // Date. `showLoginModal` serialises on a module-level queue, so a test
    // that throws before settling `pending` would wedge every later test
    // behind it — the try/finally guarantees cleanup either way.
    vi.useFakeTimers();
    let pending: Promise<unknown> | undefined;
    try {
      neverSettle();
      pending = startRelayLogin();
      await settleMicrotasks();

      await vi.advanceTimersByTimeAsync(3_000);

      const countdown = document.getElementById('signet-login-countdown');
      expect(countdown?.textContent).toMatch(/^Approve on your phone · 4:5[6-7] remaining$/);
    } finally {
      vi.useRealTimers();
      if (pending) await cancelAndDrain(pending);
    }
  });

  it('shows the named expiry state and relabels Back to Start again', async () => {
    vi.mocked(waitForAuthResponse).mockRejectedValue(codedError('expired'));

    const pending = startRelayLogin();
    await settleMicrotasks();

    try {
      expect(statusText()).toContain('expired');
      const back = document.querySelector<HTMLButtonElement>('[data-action="back"]');
      expect(back?.textContent).toBe('Start again');
    } finally {
      await cancelAndDrain(pending);
    }
  });

  it('stops the countdown ticker on settle instead of leaking it', async () => {
    // A leaked interval keeps a dead dialog ticking — the thing Task 9 Step 3
    // exists to prevent.
    const clearIntervalSpy = vi.spyOn(window, 'clearInterval');
    neverSettle();
    const pending = startRelayLogin();
    await settleMicrotasks();

    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
    await pending;

    expect(clearIntervalSpy).toHaveBeenCalled();
  });

  it('stops the countdown ticker when the wait rejects, not just on settle', async () => {
    const clearIntervalSpy = vi.spyOn(window, 'clearInterval');
    vi.mocked(waitForAuthResponse).mockRejectedValue(codedError('relay-error'));

    const pending = startRelayLogin();
    await settleMicrotasks();

    expect(clearIntervalSpy).toHaveBeenCalled();
    await cancelAndDrain(pending);
  });
});

describe('the relay the cross-device sign-in uses', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    vi.mocked(waitForAuthResponse).mockReset();
    neverSettle();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it("defaults to the Signet app's own relay, which serves gift wraps", async () => {
    // The default was relay.damus.io. It accepts the signer's gift wrap, then
    // refuses kind-1059 reads to an unauthenticated client — and its AUTH is
    // misconfigured, so no client can fetch one. Every cross-device sign-in on
    // the default failed, silently. relay.trotters.cc is what signet-app uses.
    const pending = login({
      appName: 'Pallasite',
      challenge: CHALLENGE,
      theme: 'dark',
      preferredMethod: 'remote-signet',
      persist: false,
    });
    await settleMicrotasks();

    try {
      expect(lastWaitCall().relayUrl).toBe('wss://relay.trotters.cc');
    } finally {
      await cancelAndDrain(pending);
    }
  });

  it('names a relay refusal and shows its reason instead of a raw code', async () => {
    vi.mocked(waitForAuthResponse).mockRejectedValue(
      Object.assign(codedError('relay-refused'), {
        reason: 'auth-required: requested filter requires authentication',
      }),
    );

    const pending = startRelayLogin();
    await settleMicrotasks();

    try {
      expect(statusText()).toContain('relay refused');
      expect(statusText()).toContain('auth-required');
    } finally {
      await cancelAndDrain(pending);
    }
  });
});
