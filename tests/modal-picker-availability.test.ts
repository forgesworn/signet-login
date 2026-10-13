import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';

import { login } from '../src/signet-login.js';
import type { EventTemplate, LoginOptions } from '../src/types.js';

async function settleMicrotasks(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

function button(choice: string): HTMLButtonElement | null {
  return document.querySelector(`[data-choice="${choice}"]`);
}

function provider() {
  const secretKey = generateSecretKey();
  return {
    getPublicKey: vi.fn(async () => getPublicKey(secretKey)),
    signEvent: vi.fn(async (event: EventTemplate) => finalizeEvent({
      ...event, created_at: event.created_at!, tags: event.tags!,
    }, secretKey)),
  };
}

describe('picker extension availability', () => {
  let pending: ReturnType<typeof login> | undefined;

  async function open(options: Partial<LoginOptions> = {}): Promise<void> {
    pending = login({ appName: 'Picker test', theme: 'dark', persist: false, ...options });
    await settleMicrotasks();
    expect(document.querySelector('#signet-login-dialog')).not.toBeNull();
    await vi.advanceTimersByTimeAsync(0);
  }

  beforeEach(() => {
    vi.useFakeTimers();
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    localStorage.clear();
    document.body.innerHTML = '';
    delete window.nostr;
    pending = undefined;
  });

  afterEach(async () => {
    document.querySelector('dialog')?.dispatchEvent(new Event('cancel', { cancelable: true }));
    if (pending) await pending;
    delete window.nostr;
    document.body.innerHTML = '';
    vi.useRealTimers();
  });

  it('offers a late provider in the same picker and signs only after selection', async () => {
    await open({ methods: ['nip07'], challenge: 'ab'.repeat(32) });
    const dialog = document.querySelector('dialog');
    expect(button('nip07')).toBeNull();

    const nostr = provider();
    window.nostr = nostr;
    await vi.advanceTimersByTimeAsync(250);

    expect(document.querySelector('dialog')).toBe(dialog);
    expect(button('nip07')).not.toBeNull();
    expect(nostr.getPublicKey).not.toHaveBeenCalled();
    expect(nostr.signEvent).not.toHaveBeenCalled();
    button('nip07')!.click();

    const session = await pending;
    expect(session?.method).toBe('nip07');
    expect(session?.authEvent.kind).toBe(21236);
    expect(nostr.getPublicKey).toHaveBeenCalledOnce();
    expect(nostr.signEvent).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(250);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores an incomplete provider and removes a provider that disappears', async () => {
    await open({ methods: ['nip07'] });
    window.nostr = { getPublicKey: async () => '11'.repeat(32) } as NonNullable<typeof window.nostr>;
    await vi.advanceTimersByTimeAsync(250);
    expect(button('nip07')).toBeNull();

    window.nostr = provider();
    await vi.advanceTimersByTimeAsync(250);
    expect(button('nip07')).not.toBeNull();
    delete window.nostr;
    await vi.advanceTimersByTimeAsync(250);
    expect(button('nip07')).toBeNull();
  });

  it('preserves Advanced, keyboard focus and the gamepad selection when a provider arrives', async () => {
    await open();
    document.querySelector<HTMLButtonElement>('[data-action="advanced"]')!.click();
    await settleMicrotasks();
    button('cancel')!.focus();
    // Sync the tracked gamepad cursor to Cancel before the new method shifts it.
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown' }));

    const nostr = provider();
    window.nostr = nostr;
    await vi.advanceTimersByTimeAsync(250);
    expect(button('nsec')).not.toBeNull();
    expect(document.querySelector('[data-action="advanced"]')).toBeNull();
    expect(document.activeElement).toBe(button('cancel'));

    const unchangedButton = button('cancel');
    await vi.advanceTimersByTimeAsync(1_000);
    expect(button('cancel')).toBe(unchangedButton);
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await expect(pending).resolves.toBeNull();
    expect(nostr.getPublicKey).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rechecks immediately when returning to the page', async () => {
    await open();
    window.nostr = provider();
    window.dispatchEvent(new Event('focus'));
    expect(button('nip07')).not.toBeNull();
    delete window.nostr;
    document.dispatchEvent(new Event('visibilitychange'));
    expect(button('nip07')).toBeNull();
  });

  it('stops observing on Escape and leaves later UI untouched', async () => {
    await open();
    document.querySelector('dialog')!.dispatchEvent(new Event('cancel', { cancelable: true }));
    await expect(pending).resolves.toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    window.nostr = provider();
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(document.querySelector('dialog')).toBeNull();
  });

  it('stops observing while another method is in progress', async () => {
    await open({ methods: ['nip07', 'bunker'], advancedMethods: [] });
    button('bunker')!.click();
    await settleMicrotasks();
    const input = document.querySelector<HTMLTextAreaElement>('#signet-login-bunker-input')!;
    input.value = 'unfinished input';
    await vi.advanceTimersByTimeAsync(0);
    expect(vi.getTimerCount()).toBe(0);
    window.nostr = provider();
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(document.querySelector('#signet-login-bunker-input')).toBe(input);
    expect(input.value).toBe('unfinished input');
    expect(button('nip07')).toBeNull();

    document.querySelector<HTMLButtonElement>('[data-action="back"]')!.click();
    await settleMicrotasks();
    expect(button('nip07')).not.toBeNull();
  });

  it('honours configured methods without starting an extension observer', async () => {
    await open({ methods: ['bunker'], advancedMethods: [] });
    expect(vi.getTimerCount()).toBe(0);
    window.nostr = provider();
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(button('nip07')).toBeNull();
    expect(button('bunker')).not.toBeNull();
  });
});
