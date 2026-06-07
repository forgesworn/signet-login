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

  it('uses relay delivery for preferredMethod=redirect so the signer tab stays alive', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      preferredMethod: 'redirect',
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
});
