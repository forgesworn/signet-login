/**
 * Platform-aware ordering and wording of the two Signet device options.
 *
 * Product guidance (mobile-first): lead the picker with the signer that lives on
 * the *other* device. On a phone that is the Signet app on "this device"; on a
 * desktop (or when the platform is unknown) it is "your phone". Only the default
 * method list adapts — an explicit `methods` order from the consumer is honoured.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { login } from '../src/signet-login.js';

const DESKTOP_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const IPHONE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

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

function setUserAgent(value: string): void {
  Object.defineProperty(window.navigator, 'userAgent', { configurable: true, value });
}

function pickerChoices(): (string | undefined)[] {
  return Array.from(document.querySelectorAll<HTMLButtonElement>('[data-choice]')).map(button => button.dataset.choice);
}

function buttonText(choice: string): string {
  return document.querySelector(`[data-choice="${choice}"]`)?.textContent ?? '';
}

async function cancelAndSettle(pending: Promise<unknown>): Promise<void> {
  document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
  await expect(pending).resolves.toBeNull();
}

describe('platform-aware device picker', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    delete (window as unknown as { nostr?: unknown }).nostr;
  });

  afterEach(() => {
    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    document.body.innerHTML = '';
    setUserAgent('Mozilla/5.0');
  });

  it('leads with the other device (remote-signet) on desktop', async () => {
    setUserAgent(DESKTOP_UA);
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('remote-signet')).toBeLessThan(choices.indexOf('local-signet'));
    expect(buttonText('remote-signet')).toContain('Use your phone');
    expect(buttonText('local-signet')).toContain('Use this device');

    await cancelAndSettle(pending);
  });

  it('leads with this device (local-signet) on a phone, calling the other one "another device"', async () => {
    setUserAgent(IPHONE_UA);
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('local-signet')).toBeLessThan(choices.indexOf('remote-signet'));
    expect(buttonText('local-signet')).toContain('Use this device');
    expect(buttonText('remote-signet')).toContain('Use another device');

    await cancelAndSettle(pending);
  });

  it('defaults to other-device-first when the platform cannot be determined', async () => {
    setUserAgent('');
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('remote-signet')).toBeLessThan(choices.indexOf('local-signet'));

    await cancelAndSettle(pending);
  });

  it('honours an explicit methods order even on desktop', async () => {
    setUserAgent(DESKTOP_UA);
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      advancedMethods: [],
      methods: ['local-signet', 'remote-signet'],
    });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('local-signet')).toBeLessThan(choices.indexOf('remote-signet'));

    await cancelAndSettle(pending);
  });
});
