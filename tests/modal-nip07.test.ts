import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';

import { login } from '../src/signet-login.js';
import type { EventTemplate } from '../src/types.js';

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
  await Promise.resolve();
}

async function waitForText(selector: string, expected: string): Promise<void> {
  for (let i = 0; i < 20; i++) {
    if (document.querySelector(selector)?.textContent === expected) return;
    await settleMicrotasks();
  }
  expect(document.querySelector(selector)?.textContent).toBe(expected);
}

function cancelNip07Flow(): void {
  document.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.click();
}

describe('NIP-07 modal flow', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    delete window.nostr;
  });

  afterEach(() => {
    cancelNip07Flow();
    document.querySelector<HTMLButtonElement>('[data-choice="cancel"]')?.click();
    document.body.innerHTML = '';
    delete window.nostr;
    vi.useRealTimers();
  });

  it('completes login with a strict Ditto-style NIP-07 provider', async () => {
    const secretKey = generateSecretKey();
    const pubkey = getPublicKey(secretKey);
    const signEvent = vi.fn(async (event: EventTemplate) => {
      if (typeof event.created_at !== 'number' || !Array.isArray(event.tags)) {
        throw new Error('strict-provider: incomplete unsigned event');
      }
      return finalizeEvent({
        kind: event.kind,
        content: event.content,
        created_at: event.created_at,
        tags: event.tags,
      }, secretKey);
    });
    window.nostr = {
      getPublicKey: async () => pubkey,
      signEvent,
    };

    const pending = login({
      appName: 'Ditto compatibility test',
      challenge: 'ab'.repeat(32),
      preferredMethod: 'nip07',
      theme: 'dark',
      persist: false,
    });
    const session = await pending;

    expect(session?.method).toBe('nip07');
    expect(session?.pubkey).toBe(pubkey);
    expect(session?.authEvent.kind).toBe(21236);
    expect(session?.authEvent.created_at).toEqual(expect.any(Number));
    expect(session?.authEvent.tags).toContainEqual(['challenge', 'ab'.repeat(32)]);
    expect(session?.authEvent.tags).toContainEqual(['app', 'Ditto compatibility test']);
    expect(session?.authEvent && verifyEvent(session.authEvent)).toBe(true);
    expect(signEvent).toHaveBeenCalledOnce();
  });

  it('times out while waiting for an extension public key', async () => {
    vi.useFakeTimers();
    window.nostr = {
      getPublicKey: () => new Promise<string>(() => {}),
      signEvent: async () => { throw new Error('unexpected signEvent'); },
    };

    const pending = login({
      appName: 'NIP-07 timeout test',
      preferredMethod: 'nip07',
      timeout: 5_000,
      theme: 'dark',
      persist: false,
    });
    await settleMicrotasks();
    expect(document.querySelector('h2')?.textContent).toBe('Waiting for your extension');

    await vi.advanceTimersByTimeAsync(5_000);
    expect(document.querySelector('#signet-login-nip07-elapsed')?.textContent)
      .toContain('nip07-get-public-key-timeout');

    cancelNip07Flow();
    await expect(pending).resolves.toBeNull();
  });

  it('times out separately while waiting for signature approval', async () => {
    vi.useFakeTimers();
    const pubkey = 'e'.repeat(64);
    window.nostr = {
      getPublicKey: async () => pubkey,
      signEvent: () => new Promise(() => {}),
    };

    const pending = login({
      appName: 'NIP-07 signature timeout test',
      preferredMethod: 'nip07',
      timeout: 5_000,
      theme: 'dark',
      persist: false,
    });
    await waitForText('#signet-login-nip07-elapsed', 'Waiting for signature approval…');

    await vi.advanceTimersByTimeAsync(5_000);
    expect(document.querySelector('#signet-login-nip07-elapsed')?.textContent)
      .toContain('nip07-sign-event-timeout');

    cancelNip07Flow();
    await expect(pending).resolves.toBeNull();
  });
});
