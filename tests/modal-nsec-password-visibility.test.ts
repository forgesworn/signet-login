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

const query = <T extends Element>(selector: string): T | null => document.querySelector<T>(selector);
const click = async (selector: string): Promise<void> => (await until(() => query<HTMLButtonElement>(selector))).click();
const type = (field: HTMLTextAreaElement, value: string): void => {
  field.value = value;
  field.dispatchEvent(new Event('input', { bubbles: true }));
};

describe('encrypted-key password visibility', () => {
  const options: LoginOptions = { appName: 'Password test', theme: 'light', methods: ['nsec'], persist: false };

  beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    localStorage.clear();
    document.body.innerHTML = '';
  });

  afterEach(() => { document.body.innerHTML = ''; });

  it('reveals and hides the password without changing its value or submitting', async () => {
    const pending = login(options);
    let completed = false;
    void pending.then(() => { completed = true; });
    await click('[data-choice="nsec"]');
    const key = await until(() => query<HTMLTextAreaElement>('#signet-login-nsec-input'));
    const row = query<HTMLElement>('#signet-login-nsec-password-row')!;
    const password = query<HTMLInputElement>('#signet-login-nsec-password')!;
    const toggle = query<HTMLButtonElement>('[data-action="toggle-password"]')!;

    expect(toggle.type).toBe('button');
    expect(toggle.getAttribute('aria-controls')).toBe(password.id);
    expect(toggle.getAttribute('aria-label')).toBe('Show password');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    expect(row.hidden).toBe(true);

    type(key, 'ncryptsec1test');
    expect(row.hidden).toBe(false);
    password.value = 'a password';
    toggle.click();
    expect(password.type).toBe('text');
    expect(password.value).toBe('a password');
    expect(toggle.getAttribute('aria-label')).toBe('Hide password');
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(toggle.getAttribute('title')).toBe('Hide password');
    expect(completed).toBe(false);

    toggle.click();
    expect(password.type).toBe('password');
    expect(password.value).toBe('a password');
    expect(toggle.getAttribute('aria-label')).toBe('Show password');

    toggle.click();
    type(key, '');
    expect(row.hidden).toBe(true);
    expect(password.type).toBe('password');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');

    type(key, 'ncryptsec1test');
    toggle.click();
    await click('[data-action="back"]');
    expect(password.value).toBe('');
    expect(password.type).toBe('password');

    await click('[data-choice="nsec"]');
    const fresh = await until(() => query<HTMLInputElement>('#signet-login-nsec-password'));
    expect(fresh.type).toBe('password');
    expect(fresh.value).toBe('');
    await click('[data-action="back"]');
    await click('[data-choice="cancel"]');
    expect(await pending).toBeNull();
  });
});
