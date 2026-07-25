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

vi.mock('signet-verify', () => ({
  waitForAuthResponse: vi.fn(() => new Promise(() => { /* overridden per test */ })),
}));

import { waitForAuthResponse } from 'signet-verify';
import { login } from '../src/signet-login.js';
import { makeAuthEvent, TEST_PRIVATE_KEY } from './helpers/auth-event.js';

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
