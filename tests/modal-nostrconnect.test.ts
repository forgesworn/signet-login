import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/signers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/signers.js')>();
  return {
    ...actual,
    createBunkerSignerFromNostrConnect: vi.fn(() => new Promise(() => { /* keep the pairing UI waiting */ })),
  };
});

vi.mock('qrcode', () => ({
  default: {
    toCanvas: vi.fn((canvas: HTMLCanvasElement) => {
      canvas.style.width = '360px';
      canvas.style.height = '360px';
      return Promise.resolve(canvas);
    }),
  },
}));

import QRCode from 'qrcode';
import { login } from '../src/signet-login.js';
import { createBunkerSignerFromNostrConnect } from '../src/signers.js';

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

async function waitForElement<T extends Element>(selector: string): Promise<T> {
  for (let i = 0; i < 20; i++) {
    const el = document.querySelector<T>(selector);
    if (el) return el;
    await settleMicrotasks();
  }
  expect(document.querySelector(selector)).not.toBeNull();
  return document.querySelector<T>(selector)!;
}

describe('NostrConnect modal flow', () => {
  beforeEach(() => {
    installDialogPolyfill();
    localStorage.clear();
    document.body.innerHTML = '';
    delete (window as unknown as { nostr?: unknown }).nostr;
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    document.querySelector<HTMLButtonElement>('[data-action="back"],[data-action="cancel"]')?.click();
    vi.clearAllMocks();
    document.body.innerHTML = '';
  });

  it('shows a large scannable QR with a copyable NostrConnect URI below it', async () => {
    const pending = login({
      appName: 'Canary',
      theme: 'dark',
      persist: false,
      preferredMethod: 'nostrconnect',
      relayUrl: 'wss://relay.trotters.cc',
      relayUrls: ['wss://relay.primal.net', 'wss://relay.trotters.cc'],
    });

    const qr = await waitForElement<HTMLCanvasElement>('#signet-login-nc-qr');
    await settleMicrotasks();
    expect(qr.width).toBe(360);
    expect(qr.height).toBe(360);
    expect(qr.style.width).toBe('360px');
    expect(qr.style.height).toBe('auto');
    expect(qr.style.maxWidth).toBe('100%');

    const uriText = await waitForElement<HTMLTextAreaElement>('#signet-login-nc-uri');
    expect(uriText.readOnly).toBe(true);
    expect(uriText.value).toMatch(/^nostrconnect:\/\/[0-9a-f]{64}\?/);
    const parsed = new URL(uriText.value);
    expect(parsed.searchParams.getAll('relay')).toEqual([
      'wss://relay.primal.net',
      'wss://relay.trotters.cc',
    ]);
    expect(uriText.value).toContain('name=Canary');

    await settleMicrotasks();
    expect(createBunkerSignerFromNostrConnect).toHaveBeenCalledWith(expect.objectContaining({
      uri: uriText.value,
      abortSignal: expect.any(AbortSignal),
    }));
    expect(QRCode.toCanvas).toHaveBeenCalledWith(qr, uriText.value, expect.objectContaining({
      width: 360,
      margin: 2,
      errorCorrectionLevel: 'L',
    }));

    document.querySelector<HTMLButtonElement>('[data-action="copy"]')?.click();
    await settleMicrotasks();
    expect(window.navigator.clipboard.writeText).toHaveBeenCalledWith(uriText.value);

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });

  it('passes timeout and status events through the NostrConnect modal flow', async () => {
    const events: Array<{ type: string; relay?: string }> = [];
    const pending = login({
      appName: 'Canary',
      theme: 'dark',
      persist: false,
      preferredMethod: 'nostrconnect',
      relayUrl: 'wss://relay.trotters.cc',
      timeout: 7_000,
      onNostrConnectStatus: event => events.push(event),
    });

    await waitForElement<HTMLTextAreaElement>('#signet-login-nc-uri');
    const call = vi.mocked(createBunkerSignerFromNostrConnect).mock.calls.at(-1)?.[0];
    expect(call).toEqual(expect.objectContaining({
      timeoutMs: 7_000,
      onStatus: expect.any(Function),
    }));

    call!.onStatus?.({
      type: 'relay-connected',
      timestamp: 1,
      relays: ['wss://relay.trotters.cc'],
      relay: 'wss://relay.trotters.cc',
    });

    const status = await waitForElement<HTMLElement>('#signet-login-nc-status');
    expect(status.textContent).toContain('Connected to relay wss://relay.trotters.cc');
    expect(events).toEqual([
      expect.objectContaining({
        type: 'relay-connected',
        relay: 'wss://relay.trotters.cc',
      }),
    ]);

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });
});
