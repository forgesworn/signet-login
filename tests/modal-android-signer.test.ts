import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { login } from '../src/signet-login.js';
import { loadPendingRedirect } from '../src/storage.js';

const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 15) Mobile Chrome/140.0.0.0';

async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

function choice(name: string): HTMLButtonElement | null {
  return document.querySelector(`[data-choice="${name}"]`);
}

describe('Android signer hand-off', () => {
  let pending: ReturnType<typeof login> | undefined;
  let hrefSetter: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    localStorage.clear();
    document.body.innerHTML = '';
    delete window.nostr;
    pending = undefined;
    // jsdom cannot navigate to intent: or nostrsigner: URLs; record the attempt instead.
    hrefSetter = vi.fn();
    vi.spyOn(window, 'location', 'get').mockReturnValue(Object.defineProperty(
      { ...window.location }, 'href', { configurable: true, get: () => 'https://app.example/', set: hrefSetter },
    ) as Location);
  });

  afterEach(async () => {
    document.querySelector('dialog')?.dispatchEvent(new Event('cancel', { cancelable: true }));
    if (pending) await pending;
    vi.restoreAllMocks();
    document.body.innerHTML = '';
    vi.useRealTimers();
  });

  async function open(methods: Parameters<typeof login>[0]['methods']): Promise<void> {
    pending = login({ appName: 'Canary', theme: 'light', persist: false, methods, advancedMethods: [] });
    await settle();
    await vi.advanceTimersByTimeAsync(0);
  }

  function decodeRequest(url: string): { kind: number; tags: string[][] } {
    const encoded = url.replace(/^intent:/, 'nostrsigner:').replace(/^nostrsigner:/, '').split('?')[0]!.split('#')[0]!;
    return JSON.parse(decodeURIComponent(encoded));
  }

  it('offers Cambium only on Android', async () => {
    await open(['cambium', 'bunker']);
    expect(choice('cambium')).toBeNull();
    document.querySelector('dialog')?.dispatchEvent(new Event('cancel', { cancelable: true }));
    await pending;

    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    document.body.innerHTML = '';
    await open(['cambium', 'bunker']);
    expect(choice('cambium')?.textContent).toContain('Open Cambium on this device');
  });

  it('targets Cambium directly with a NIP-55 intent carrying the login request', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['cambium', 'bunker']);
    choice('cambium')!.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(document.querySelector('h2')?.textContent).toBe('Approve in Cambium');
    const link = document.querySelector<HTMLAnchorElement>('[data-action="open-android-signer"]')!;
    const href = link.getAttribute('href')!;
    expect(href).toMatch(/^intent:/);
    expect(href).toMatch(/#Intent;scheme=nostrsigner;package=dev\.forgesworn\.cambium;end$/);
    expect(link.hasAttribute('aria-disabled')).toBe(false);
    expect(hrefSetter).toHaveBeenCalledWith(href);
    expect(link.textContent).toBe('Open Cambium');

    const event = decodeRequest(href);
    expect(event.kind).toBe(21236);
    expect(event.tags.map(tag => tag[0])).toEqual(expect.arrayContaining(['challenge', 'origin', 'app']));
    expect(loadPendingRedirect()).not.toBeNull();
  });

  it('keeps the plain nostrsigner: request for the generic Android signer', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['amber', 'bunker']);
    choice('amber')!.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(document.querySelector('h2')?.textContent).toBe('Approve in your Android signer');
    const link = document.querySelector<HTMLAnchorElement>('[data-action="open-android-signer"]')!;
    expect(link.getAttribute('href')).toMatch(/^nostrsigner:/);
    expect(link.getAttribute('href')).not.toContain('package=');
    expect(link.textContent).toBe('Open signer app');
  });

  it('shows progress, then a retry hint when the signer app does not open', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['cambium', 'bunker']);
    choice('cambium')!.click();
    await vi.advanceTimersByTimeAsync(0);

    const status = document.querySelector<HTMLElement>('[data-android-signer-status]')!;
    expect(status.textContent).toBe('Opening Cambium…');
    await vi.advanceTimersByTimeAsync(1800);
    expect(status.textContent).toContain('If Cambium didn’t open');

    // The hint is retryable: tapping the link starts the progress message again.
    document.querySelector<HTMLAnchorElement>('[data-action="open-android-signer"]')!.click();
    expect(status.textContent).toBe('Opening Cambium…');
  });

  it('switches to a waiting message when the page is hidden by the hand-off', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['cambium', 'bunker']);
    choice('cambium')!.click();
    await vi.advanceTimersByTimeAsync(0);

    const status = document.querySelector<HTMLElement>('[data-android-signer-status]')!;
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    expect(status.textContent).toBe('Waiting for approval in Cambium…');
    await vi.advanceTimersByTimeAsync(5000);
    expect(status.textContent).toBe('Waiting for approval in Cambium…');
  });

  it('Back returns to the picker and discards the pending request', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['cambium', 'bunker']);
    choice('cambium')!.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(loadPendingRedirect()).not.toBeNull();

    document.querySelector<HTMLButtonElement>('[data-action="back"]')!.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(choice('cambium')).not.toBeNull();
    expect(loadPendingRedirect()).toBeNull();
  });

  it('Cancel ends the whole login', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA);
    await open(['cambium', 'bunker']);
    choice('cambium')!.click();
    await vi.advanceTimersByTimeAsync(0);

    document.querySelector<HTMLButtonElement>('[data-action="cancel"]')!.click();
    await expect(pending).resolves.toBeNull();
    expect(loadPendingRedirect()).toBeNull();
  });
});
