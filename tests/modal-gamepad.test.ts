/**
 * Regression coverage for gamepad-driven Signet modal navigation.
 *
 * Pallasite polls a physical Bluetooth gamepad and dispatches synthetic
 * KeyboardEvents (Arrow*, Enter, Escape) on window while the Signet <dialog>
 * is open. The host page can also move DOM focus behind the dialog, so the
 * modal must click its tracked selection index rather than activeElement.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

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

function dispatchSyntheticKey(key: string, code = key): void {
  window.dispatchEvent(new KeyboardEvent('keydown', { key, code, bubbles: true }));
}

async function settleMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe('gamepad modal navigation', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    delete window.nostr;
    Object.defineProperty(window.navigator, 'userAgent', {
      configurable: true,
      value: 'Mozilla/5.0',
    });
    Object.defineProperty(HTMLElement.prototype, 'offsetParent', {
      configurable: true,
      get() {
        return this.isConnected ? document.body : null;
      },
    });
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('synthetic Enter clicks the tracked selection even when host focus was stolen', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    const dialog = document.getElementById('signet-login-dialog');
    expect(dialog).toBeInstanceOf(HTMLDialogElement);

    // Desktop picker order without NIP-07/Amber:
    // redirect, qr, bunker, nostrconnect, nsec, cancel.
    for (let i = 0; i < 5; i++) dispatchSyntheticKey('ArrowDown');
    expect(document.activeElement?.textContent?.trim()).toBe('Cancel');

    const hostButton = document.createElement('button');
    hostButton.textContent = 'host overlay button';
    document.body.appendChild(hostButton);
    hostButton.focus();
    expect(document.activeElement).toBe(hostButton);

    dispatchSyntheticKey('Enter');
    await expect(pending).resolves.toBeNull();
    expect(document.getElementById('signet-login-dialog')).toBeNull();
  });

  it('synthetic Escape prefers Back on sub-screens instead of cancelling the whole flow', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    // Move to the nsec method and select it. This opens a sub-screen with Back.
    for (let i = 0; i < 4; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await settleMicrotasks();
    expect(document.querySelector('#signet-login-nsec-input')).toBeInstanceOf(HTMLTextAreaElement);

    dispatchSyntheticKey('Escape');
    await settleMicrotasks();
    expect(document.querySelector('#signet-login-nsec-input')).toBeNull();
    expect(document.querySelector('[data-choice="redirect"]')).toBeInstanceOf(HTMLButtonElement);

    // Cleanly resolve the still-open picker.
    for (let i = 0; i < 5; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await expect(pending).resolves.toBeNull();
  });
});
