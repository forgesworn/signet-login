/**
 * Stable ordering with a platform-aware *highlight* for the two Signet options.
 *
 * Switching the order between visits is disorienting, so the picker keeps the
 * "other device" option (remote-signet) at the top on every platform. The
 * platform only decides which option is highlighted as the likely choice: on a
 * phone that is "use this device", on a desktop (or unknown) it is "use your
 * phone". Wording adapts too — the remote option is "your phone" on desktop and
 * "another device" on a phone. Only the default method list is affected; an
 * explicit `methods` order from the consumer is honoured.
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

/** The data-choice of the single highlighted (recommended) button, if any. */
function highlightedChoice(): string | undefined {
  return document.querySelector<HTMLButtonElement>('[data-choice][data-primary="true"]')?.dataset.choice;
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

  it('keeps the other-device option at the top and highlights it on desktop', async () => {
    setUserAgent(DESKTOP_UA);
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('remote-signet')).toBeLessThan(choices.indexOf('local-signet'));
    expect(highlightedChoice()).toBe('remote-signet');
    expect(buttonText('remote-signet')).toContain('Use your phone');
    expect(buttonText('local-signet')).toContain('Use this device');

    await cancelAndSettle(pending);
  });

  it('keeps the same order on a phone but highlights this device instead', async () => {
    setUserAgent(IPHONE_UA);
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    // Order is identical to desktop — only the highlight moves.
    expect(choices.indexOf('remote-signet')).toBeLessThan(choices.indexOf('local-signet'));
    expect(highlightedChoice()).toBe('local-signet');
    expect(buttonText('local-signet')).toContain('Use this device');
    expect(buttonText('remote-signet')).toContain('Use another device');

    await cancelAndSettle(pending);
  });

  it('highlights the other device when the platform cannot be determined', async () => {
    setUserAgent('');
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    const choices = pickerChoices();
    expect(choices.indexOf('remote-signet')).toBeLessThan(choices.indexOf('local-signet'));
    expect(highlightedChoice()).toBe('remote-signet');

    await cancelAndSettle(pending);
  });

  it('honours an explicit methods order while still highlighting the likely option', async () => {
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
    // Explicit order preserved (local first), but the desktop-likely option is
    // still the highlighted one even though it sits second.
    expect(choices.indexOf('local-signet')).toBeLessThan(choices.indexOf('remote-signet'));
    expect(highlightedChoice()).toBe('remote-signet');

    await cancelAndSettle(pending);
  });
});
