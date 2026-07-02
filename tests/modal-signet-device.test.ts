import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('signet-verify', () => ({
  waitForAuthResponse: vi.fn(() => new Promise(() => { /* never resolves in UI tests */ })),
}));

import { waitForAuthResponse } from 'signet-verify';
import { login } from '../src/signet-login.js';

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

async function settleMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function dispatchPersistedPageShow(): void {
  const event = new Event('pageshow') as PageTransitionEvent;
  Object.defineProperty(event, 'persisted', { value: true });
  window.dispatchEvent(event);
}

describe('same-device Signet modal flow', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    delete (window as unknown as { nostr?: unknown }).nostr;
    vi.spyOn(window, 'open').mockImplementation(() => null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = '';
  });

  it('uses relay delivery for preferredMethod=local-signet so the signer tab stays alive', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'local-signet',
      relayUrl: 'wss://relay.trotters.cc',
      signetAppOrigin: 'https://mysignet.app',
      persist: false,
    });
    await settleMicrotasks();

    const dialog = document.getElementById('signet-login-dialog');
    expect(dialog).toBeInstanceOf(HTMLDialogElement);

    const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement | null;
    expect(link).toBeInstanceOf(HTMLAnchorElement);

    const url = new URL(link!.href);
    expect(url.origin).toBe('https://mysignet.app');
    expect(url.searchParams.get('auth')).toBe('1');
    expect(url.searchParams.get('relay')).toBe('wss://relay.trotters.cc');
    expect(url.searchParams.get('sessionPubkey')).toMatch(/^[0-9a-f]{64}$/);

    expect(window.open).toHaveBeenCalledWith(
      expect.stringContaining('sessionPubkey='),
      '_blank',
      'noopener,noreferrer',
    );
    expect(waitForAuthResponse).toHaveBeenCalledWith(expect.objectContaining({
      relayUrl: 'wss://relay.trotters.cc',
      expectedOrigin: window.location.origin,
    }));

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('keeps relayUrl as the Signet relay when NostrConnect relayUrls are also configured', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'local-signet',
      relayUrl: 'wss://relay.trotters.cc',
      relayUrls: ['wss://relay.primal.net', 'wss://nos.lol'],
      signetAppOrigin: 'https://mysignet.app',
      persist: false,
    });
    await settleMicrotasks();

    const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement | null;
    expect(link).toBeInstanceOf(HTMLAnchorElement);

    const url = new URL(link!.href);
    expect(url.searchParams.get('relay')).toBe('wss://relay.trotters.cc');
    expect(waitForAuthResponse).toHaveBeenCalledWith(expect.objectContaining({
      relayUrl: 'wss://relay.trotters.cc',
    }));

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('keeps legacy preferredMethod=redirect as the local Signet alias', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'redirect',
      relayUrl: 'wss://relay.trotters.cc',
      signetAppOrigin: 'https://mysignet.app',
      persist: false,
    });
    await settleMicrotasks();

    const link = document.getElementById('signet-login-open-signet') as HTMLAnchorElement | null;
    expect(link).toBeInstanceOf(HTMLAnchorElement);
    const url = new URL(link!.href);
    expect(url.searchParams.get('relay')).toBe('wss://relay.trotters.cc');
    expect(url.searchParams.get('sessionPubkey')).toMatch(/^[0-9a-f]{64}$/);

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('treats browser Back from the Signet handoff as cancellation', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'local-signet',
      relayUrl: 'wss://relay.trotters.cc',
      signetAppOrigin: 'https://mysignet.app',
      persist: false,
    });
    await settleMicrotasks();

    expect(document.getElementById('signet-login-dialog')).toBeInstanceOf(HTMLDialogElement);

    dispatchPersistedPageShow();

    await expect(pending).resolves.toBeNull();
    expect(document.getElementById('signet-login-dialog')).toBeNull();
  });

  describe('abandoned waitForAuthResponse after Back/Cancel', () => {
    afterEach(() => {
      // signet-verify's waitForAuthResponse has no cancellation hook (see
      // src/modal.ts comment near runRedirectFlow) — restore the default
      // "never resolves" implementation other tests in this file rely on.
      vi.mocked(waitForAuthResponse).mockReset();
      vi.mocked(waitForAuthResponse).mockImplementation(() => new Promise(() => { /* never resolves in UI tests */ }));
    });

    it('ignores a late rejection from an abandoned attempt instead of mutating a later attempt\'s UI', async () => {
      let rejectFirst!: (err: unknown) => void;
      const first = new Promise<never>((_resolve, reject) => { rejectFirst = reject; });
      vi.mocked(waitForAuthResponse)
        .mockImplementationOnce(() => first)
        .mockImplementationOnce(() => new Promise(() => { /* second attempt: left pending */ }));

      const pending = login({
        appName: 'Pallasite',
        theme: 'dark',
        relayUrl: 'wss://relay.trotters.cc',
        signetAppOrigin: 'https://mysignet.app',
        persist: false,
      });
      await settleMicrotasks();

      // First attempt: pick "remote-signet" (QR flow), which calls
      // waitForAuthResponse for the first time.
      document.querySelector<HTMLButtonElement>('[data-choice="remote-signet"]')?.click();
      await settleMicrotasks();
      expect(document.getElementById('signet-login-status')).not.toBeNull();

      // Back out to the picker WITHOUT the first waitForAuthResponse ever
      // settling — this is the abandoned call; its relay subscription has
      // no cancellation hook and keeps running (see fix comment).
      document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
      await settleMicrotasks();

      // Second attempt: pick "remote-signet" again. The dialog is reused —
      // a NEW #signet-login-status element replaces the first one.
      document.querySelector<HTMLButtonElement>('[data-choice="remote-signet"]')?.click();
      await settleMicrotasks();
      const secondStatus = document.getElementById('signet-login-status');
      expect(secondStatus).not.toBeNull();
      expect(secondStatus?.textContent).toMatch(/Waiting/);

      // The abandoned first call now rejects late. Without the settled
      // guard this would overwrite the SECOND (current) attempt's status
      // text with a stale error from a flow the user already left.
      rejectFirst(new Error('stale-abandoned-error'));
      await settleMicrotasks();

      expect(document.getElementById('signet-login-status')?.textContent).toMatch(/Waiting/);
      expect(document.getElementById('signet-login-status')?.textContent).not.toContain('stale-abandoned-error');

      // Clean up: back out of the (still-pending) second attempt to the
      // picker, then cancel the picker itself to resolve the overall login.
      document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
      await settleMicrotasks();
      document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
      await expect(pending).resolves.toBeNull();
    });
  });
});
