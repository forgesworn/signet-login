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
import { hexToBytesLocal } from '../src/storage.js';
import { getPublicKey } from 'nostr-tools/pure';

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

function dispatchSyntheticCode(code: string): void {
  window.dispatchEvent(new KeyboardEvent('keydown', { code, bubbles: true }));
}

async function settleMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function activeHeading(): string {
  return document.querySelector('h2')?.textContent ?? '';
}

async function cancelActiveLogin(): Promise<void> {
  document.querySelector<HTMLButtonElement>('[data-choice="cancel"],[data-action="cancel"]')?.click();
  await settleMicrotasks();
}

async function waitForActiveDialog(): Promise<HTMLDialogElement> {
  for (let i = 0; i < 20; i++) {
    const dialog = document.getElementById('signet-login-dialog');
    if (dialog instanceof HTMLDialogElement) return dialog;
    await settleMicrotasks();
  }
  expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
  return document.getElementById('signet-login-dialog') as HTMLDialogElement;
}

async function completeActiveNsecLogin(rawPrivateKeyHex: string): Promise<void> {
  // Flat picker order without NIP-07/Amber (other device stays on top):
  // remote-signet, local-signet, bunker, nostrconnect, nsec, cancel.
  for (let i = 0; i < 4; i++) dispatchSyntheticKey('ArrowDown');
  dispatchSyntheticKey('Enter');
  await settleMicrotasks();

  const input = document.querySelector<HTMLTextAreaElement>('#signet-login-nsec-input');
  expect(input).toBeInstanceOf(HTMLTextAreaElement);
  input!.value = rawPrivateKeyHex;
  document.querySelector<HTMLButtonElement>('[data-action="connect"]')?.click();
  await settleMicrotasks();
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
    document.querySelector<HTMLButtonElement>('[data-choice="cancel"],[data-action="cancel"],[data-action="back"]')?.click();
    document.body.innerHTML = '';
  });

  it('synthetic Enter clicks the tracked selection even when host focus was stolen', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    const dialog = document.getElementById('signet-login-dialog');
    expect(dialog).toBeInstanceOf(HTMLDialogElement);

    // Default picker order without NIP-07/Amber (other device stays on top):
    // remote-signet, local-signet, Advanced, cancel.
    for (let i = 0; i < 3; i++) dispatchSyntheticKey('ArrowDown');
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

  it('navigates with Arrow code even when key is blank', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    expect((document.activeElement as HTMLElement | null)?.dataset.choice).toBe('remote-signet');

    dispatchSyntheticCode('ArrowDown');
    expect((document.activeElement as HTMLElement | null)?.dataset.choice).toBe('local-signet');

    dispatchSyntheticCode('ArrowUp');
    expect((document.activeElement as HTMLElement | null)?.dataset.choice).toBe('remote-signet');

    for (let i = 0; i < 3; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await expect(pending).resolves.toBeNull();
  });

  it('does not depend on offsetParent for dialog button visibility', async () => {
    Object.defineProperty(HTMLElement.prototype, 'offsetParent', {
      configurable: true,
      get() {
        return null;
      },
    });

    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    dispatchSyntheticKey('ArrowDown');
    expect((document.activeElement as HTMLElement | null)?.dataset.choice).toBe('local-signet');

    for (let i = 0; i < 2; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await expect(pending).resolves.toBeNull();
  });

  it('synthetic arrows can escape a focused textarea', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    // Move to the nsec method and select it. This opens a sub-screen with a
    // textarea plus Back / Sign in buttons.
    for (let i = 0; i < 4; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await settleMicrotasks();

    const input = document.querySelector<HTMLTextAreaElement>('#signet-login-nsec-input');
    expect(input).toBeInstanceOf(HTMLTextAreaElement);
    input?.focus();
    expect(document.activeElement).toBe(input);

    input?.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', code: 'ArrowDown', bubbles: true }));
    expect((document.activeElement as HTMLElement | null)?.dataset.action).toBe('connect');

    dispatchSyntheticKey('Escape');
    await settleMicrotasks();
    const cancel = document.querySelector<HTMLButtonElement>('[data-choice="cancel"]');
    expect(cancel).toBeInstanceOf(HTMLButtonElement);
    cancel?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('synthetic Escape prefers Back on sub-screens instead of cancelling the whole flow', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
    await settleMicrotasks();

    // Move to the nsec method and select it. This opens a sub-screen with Back.
    for (let i = 0; i < 4; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await settleMicrotasks();
    expect(document.querySelector('#signet-login-nsec-input')).toBeInstanceOf(HTMLTextAreaElement);

    dispatchSyntheticKey('Escape');
    await settleMicrotasks();
    expect(document.querySelector('#signet-login-nsec-input')).toBeNull();
    expect(document.querySelector('[data-choice="local-signet"]')).toBeInstanceOf(HTMLButtonElement);

    // Cleanly resolve the still-open picker.
    for (let i = 0; i < 5; i++) dispatchSyntheticKey('ArrowDown');
    dispatchSyntheticKey('Enter');
    await expect(pending).resolves.toBeNull();
  });

  it('serializes overlapping booth player logins into one active modal', async () => {
    const playerOne = login({ appName: 'Prague Booth P1', theme: 'dark', persist: false });
    const playerTwo = login({ appName: 'Prague Booth P2', theme: 'dark', persist: false });
    await settleMicrotasks();

    expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
    expect(activeHeading()).toContain('Prague Booth P1');

    await cancelActiveLogin();
    await expect(playerOne).resolves.toBeNull();
    await settleMicrotasks();

    expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
    expect(activeHeading()).toContain('Prague Booth P2');

    await cancelActiveLogin();
    await expect(playerTwo).resolves.toBeNull();
    expect(document.getElementById('signet-login-dialog')).toBeNull();
  });

  it('groups power-user methods behind Advanced by default', async () => {
    const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false });
    await settleMicrotasks();

    expect(document.querySelector('[data-choice="bunker"]')).toBeNull();
    expect(document.querySelector('[data-choice="nostrconnect"]')).toBeNull();
    expect(document.querySelector('[data-choice="nsec"]')).toBeNull();

    const advanced = document.querySelector<HTMLButtonElement>('[data-action="advanced"]');
    expect(advanced).toBeInstanceOf(HTMLButtonElement);
    advanced?.click();
    await settleMicrotasks();

    expect(document.querySelector('[data-choice="bunker"]')).toBeInstanceOf(HTMLButtonElement);
    expect(document.querySelector('[data-choice="nostrconnect"]')).toBeInstanceOf(HTMLButtonElement);
    expect(document.querySelector('[data-choice="nsec"]')).toBeInstanceOf(HTMLButtonElement);

    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('honours method filtering and order', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      methods: ['remote-signet', 'local-signet'],
      advancedMethods: [],
    });
    await settleMicrotasks();

    const choices = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-choice]'))
      .map(button => button.dataset.choice);
    expect(choices).toEqual(['remote-signet', 'local-signet', 'cancel']);
    expect(document.querySelector('[data-action="advanced"]')).toBeNull();

    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('keeps legacy redirect and qr filters as aliases', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      methods: ['qr', 'redirect'],
      advancedMethods: [],
    });
    await settleMicrotasks();

    const choices = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-choice]'))
      .map(button => button.dataset.choice);
    expect(choices).toEqual(['qr', 'redirect', 'cancel']);
    expect(document.querySelector('[data-action="advanced"]')).toBeNull();

    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('normalizes legacy aliases when grouping advanced methods', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      methods: ['local-signet', 'remote-signet'],
      advancedMethods: ['redirect'],
    });
    await settleMicrotasks();

    expect(document.querySelector('[data-choice="local-signet"]')).toBeNull();
    expect(document.querySelector('[data-choice="remote-signet"]')).toBeInstanceOf(HTMLButtonElement);

    document.querySelector<HTMLButtonElement>('[data-action="advanced"]')?.click();
    await settleMicrotasks();

    expect(document.querySelector('[data-choice="local-signet"]')).toBeInstanceOf(HTMLButtonElement);
    expect(document.querySelector('[data-choice="remote-signet"]')).toBeInstanceOf(HTMLButtonElement);

    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('hides bunker QR scanning when camera APIs are unavailable', async () => {
    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      preferredMethod: 'bunker',
    });
    await settleMicrotasks();

    expect(document.querySelector('#signet-login-bunker-input')).toBeInstanceOf(HTMLTextAreaElement);
    expect(document.querySelector('[data-action="scan"]')).toBeNull();

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('shows bunker QR scanning when camera APIs are available', async () => {
    Object.defineProperty(window.navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: async () => ({ getTracks: () => [] }) },
    });

    const pending = login({
      appName: 'Pallasite',
      theme: 'dark',
      persist: false,
      preferredMethod: 'bunker',
    });
    await settleMicrotasks();

    expect(document.querySelector('#signet-login-bunker-input')).toBeInstanceOf(HTMLTextAreaElement);
    expect(document.querySelector('[data-action="scan"]')).toBeInstanceOf(HTMLButtonElement);

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('handles Prague booth player count combinations without modal leaks', async () => {
    const cases = [
      ['one booth / one player', ['Prague Booth A P1']],
      ['one booth / two players', ['Prague Booth A P1', 'Prague Booth A P2']],
      ['two booths / one player each', ['Prague Booth A P1', 'Prague Booth B P1']],
      ['two booths / booth A two players, booth B one player', ['Prague Booth A P1', 'Prague Booth A P2', 'Prague Booth B P1']],
      ['two booths / two players each', ['Prague Booth A P1', 'Prague Booth A P2', 'Prague Booth B P1', 'Prague Booth B P2']],
    ];

    for (const [label, appNames] of cases) {
      const pending = appNames.map(appName => login({ appName, theme: 'dark', persist: false }));

      for (let i = 0; i < appNames.length; i++) {
        await waitForActiveDialog();
        expect(document.querySelectorAll('#signet-login-dialog'), label).toHaveLength(1);
        expect(activeHeading(), label).toContain(appNames[i]);
        await cancelActiveLogin();
        await expect(pending[i], label).resolves.toBeNull();
        await settleMicrotasks();
      }

      expect(document.getElementById('signet-login-dialog'), label).toBeNull();
      await expect(Promise.all(pending), label).resolves.toEqual(appNames.map(() => null));
    }
  });

  it('preserves FIFO order and returns distinct sessions for four overlapping players', async () => {
    const privateKeys = [
      '01'.repeat(32),
      '02'.repeat(32),
      '03'.repeat(32),
      '04'.repeat(32),
    ];
    const appNames = ['Prague Booth A P1', 'Prague Booth A P2', 'Prague Booth B P1', 'Prague Booth B P2'];
    const pending = appNames.map(appName => login({ appName, theme: 'dark', persist: false, advancedMethods: [] }));

    for (let i = 0; i < appNames.length; i++) {
      await waitForActiveDialog();
      expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
      expect(activeHeading()).toContain(appNames[i]);
      await completeActiveNsecLogin(privateKeys[i]);
    }

    const sessions = await Promise.all(pending);
    expect(document.getElementById('signet-login-dialog')).toBeNull();
    expect(sessions.map(s => s?.method)).toEqual(['nsec', 'nsec', 'nsec', 'nsec']);
    expect(sessions.map(s => s?.pubkey)).toEqual(privateKeys.map(sk => getPublicKey(hexToBytesLocal(sk))));
    expect(new Set(sessions.map(s => s?.pubkey)).size).toBe(4);
    expect(localStorage.getItem('signet:login.pubkey')).toBeNull();
  });

  it('keeps queued logins usable after a validation failure', async () => {
    const invalid = login({ appName: '', theme: 'dark', persist: false });
    const valid = login({ appName: 'Prague Booth Recovery', theme: 'dark', persist: false });

    await expect(invalid).rejects.toThrow(/appName-required/);
    await waitForActiveDialog();

    expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
    expect(activeHeading()).toContain('Prague Booth Recovery');
    await cancelActiveLogin();
    await expect(valid).resolves.toBeNull();
    expect(document.getElementById('signet-login-dialog')).toBeNull();
  });

  it('stress-cancels many overlapping booth requests without duplicate dialogs', async () => {
    const total = 24;
    const pending = Array.from({ length: total }, (_, i) =>
      login({ appName: `Prague Stress Player ${String(i + 1).padStart(2, '0')}`, theme: 'dark', persist: false }),
    );

    for (let i = 0; i < total; i++) {
      await waitForActiveDialog();
      expect(document.querySelectorAll('#signet-login-dialog')).toHaveLength(1);
      expect(activeHeading()).toContain(`Prague Stress Player ${String(i + 1).padStart(2, '0')}`);
      await cancelActiveLogin();
      await expect(pending[i]).resolves.toBeNull();
      await settleMicrotasks();
    }

    expect(document.getElementById('signet-login-dialog')).toBeNull();
    await expect(Promise.all(pending)).resolves.toEqual(Array.from({ length: total }, () => null));
  });
});
