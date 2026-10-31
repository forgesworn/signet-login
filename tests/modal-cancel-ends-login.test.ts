import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { login } from '../src/signet-login.js';
import type { LoginOptions } from '../src/types.js';

async function until<T extends Element>(get: () => T | null): Promise<T> {
  for (let i = 0; i < 200; i++) {
    const found = get();
    if (found) return found;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error('Sign-in did not reach the expected screen');
}

const click = async (selector: string): Promise<void> =>
  (await until(() => document.querySelector<HTMLButtonElement>(selector))).click();

describe('Cancel on a waiting screen', () => {
  const options: LoginOptions = { appName: 'Cancel test', theme: 'light', challenge: 'ab'.repeat(32), methods: ['nip07'], persist: false };

  beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    localStorage.clear();
    document.body.innerHTML = '';
    window.nostr = {
      getPublicKey: () => new Promise<string>(() => {}),
      signEvent: () => new Promise<never>(() => {}),
    } as unknown as NonNullable<typeof window.nostr>;
  });

  afterEach(() => {
    delete window.nostr;
    document.body.innerHTML = '';
  });

  it('ends the whole login and releases the next one', async () => {
    const pending = login(options);
    await click('[data-choice="nip07"]');
    await click('[data-action="cancel"]');
    expect(await pending).toBeNull();
    expect(document.querySelector('dialog')).toBeNull();
  });

  it('is not what Back does: Back returns to the picker', async () => {
    const pending = login(options);
    await click('[data-choice="nip07"]');
    await click('[data-action="back"]');
    const picker = await until(() => document.querySelector<HTMLButtonElement>('[data-choice="nip07"]'));
    expect(picker).not.toBeNull();
    expect(document.querySelector('dialog')).not.toBeNull();
    await click('[data-choice="cancel"]');
    expect(await pending).toBeNull();
    expect(document.querySelector('dialog')).toBeNull();
  });
});
