/**
 * The paste-a-key route: a plain nsec signs in as before, and a NIP-49
 * ncryptsec reveals a password field, decrypts in the browser, and wipes
 * both fields once the signer holds the key.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { nsecEncode } from 'nostr-tools/nip19';
import { encrypt as nip49Encrypt } from 'nostr-tools/nip49';

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
  for (let i = 0; i < 4; i++) await Promise.resolve();
}

// Wrapped, so awaiting the helper does not adopt (and wait on) the login itself.
async function openNsecRoute(): Promise<{ pending: ReturnType<typeof login> }> {
  const pending = login({ appName: 'Pallasite', theme: 'dark', persist: false, advancedMethods: [] });
  await settleMicrotasks();
  document.querySelector<HTMLButtonElement>('[data-choice="nsec"]')?.click();
  await settleMicrotasks();
  expect(document.querySelector('#signet-login-nsec-input')).toBeInstanceOf(HTMLTextAreaElement);
  return { pending };
}

const $ = <T extends Element>(selector: string): T => {
  const el = document.querySelector<T>(selector);
  expect(el).not.toBeNull();
  return el!;
};

describe('paste-a-key modal route', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
  });

  afterEach(async () => {
    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await settleMicrotasks();
    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    await settleMicrotasks();
    document.body.innerHTML = '';
  });

  it('keeps the password field hidden for a plain nsec', async () => {
    const sk = generateSecretKey();
    const { pending } = await openNsecRoute();
    const input = $<HTMLTextAreaElement>('#signet-login-nsec-input');
    input.value = nsecEncode(sk);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    expect($<HTMLElement>('#signet-login-nsec-password-row').hidden).toBe(true);

    $<HTMLButtonElement>('[data-action="connect"]').click();
    const session = await pending;
    expect(session?.method).toBe('nsec');
    expect(session?.pubkey).toBe(getPublicKey(sk));
  });

  it('reveals the password field when an ncryptsec is pasted and refuses to submit without it', async () => {
    const sk = generateSecretKey();
    const ncryptsec = nip49Encrypt(sk, 'correct horse', 4);
    const { pending } = await openNsecRoute();
    const input = $<HTMLTextAreaElement>('#signet-login-nsec-input');
    input.value = ncryptsec;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    expect($<HTMLElement>('#signet-login-nsec-password-row').hidden).toBe(false);

    $<HTMLButtonElement>('[data-action="connect"]').click();
    await settleMicrotasks();
    expect($<HTMLElement>('#signet-login-nsec-status').textContent).toMatch(/password/i);
    // Still on the paste screen: nothing resolved.
    expect(document.querySelector('#signet-login-nsec-input')).toBeInstanceOf(HTMLTextAreaElement);

    $<HTMLInputElement>('#signet-login-nsec-password').value = 'wrong';
    $<HTMLButtonElement>('[data-action="connect"]').click();
    await settleMicrotasks();
    expect($<HTMLElement>('#signet-login-nsec-status').textContent).toMatch(/wrong password/i);

    $<HTMLInputElement>('#signet-login-nsec-password').value = 'correct horse';
    $<HTMLButtonElement>('[data-action="connect"]').click();
    const session = await pending;
    expect(session?.method).toBe('nsec');
    expect(session?.pubkey).toBe(getPublicKey(sk));
    expect(session?.signer.capabilities.canSignEvents).toBe(true);
  });

  it('wipes both fields once the signer holds the key and persists nothing', async () => {
    const sk = generateSecretKey();
    const { pending } = await openNsecRoute();
    const input = $<HTMLTextAreaElement>('#signet-login-nsec-input');
    input.value = nip49Encrypt(sk, 'pw', 4);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    const password = $<HTMLInputElement>('#signet-login-nsec-password');
    password.value = 'pw';
    // A real keyboard's Enter in the password field also submits; jsdom
    // cannot dispatch a trusted key event, and the modal's gamepad
    // navigation deliberately owns synthetic ones, so click here.
    $<HTMLButtonElement>('[data-action="connect"]').click();
    expect(input.value).toBe('');
    expect(password.value).toBe('');
    const session = await pending;
    expect(session?.pubkey).toBe(getPublicKey(sk));
    expect(localStorage.length).toBe(0);
  });
});
