import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/signers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/signers.js')>();
  return {
    ...actual,
    createBunkerSignerFromNostrConnect: vi.fn(() => new Promise(() => { /* keep the pairing UI waiting */ })),
  };
});

import jsQR from 'jsqr';
import { encode } from '@forgesworn/qr';
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

/** A recording 2D context: jsdom has no canvas, so capture the fillRect calls and rasterise them. */
function stubCanvas(): { rects: Array<{ x: number; y: number; w: number; h: number; fill: string }> } {
  const rects: Array<{ x: number; y: number; w: number; h: number; fill: string }> = [];
  const context = {
    fillStyle: '',
    fillRect(x: number, y: number, w: number, h: number) { rects.push({ x, y, w, h, fill: this.fillStyle }); },
  };
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context as unknown as CanvasRenderingContext2D);
  return { rects };
}

function rasterise(rects: ReturnType<typeof stubCanvas>['rects'], side: number): Uint8ClampedArray {
  const pixels = new Uint8ClampedArray(side * side * 4);
  for (const r of rects) {
    const value = r.fill === '#ffffff' ? 255 : 0;
    for (let y = r.y; y < r.y + r.h; y++) {
      for (let x = r.x; x < r.x + r.w; x++) {
        const i = (y * side + x) * 4;
        pixels[i] = pixels[i + 1] = pixels[i + 2] = value;
        pixels[i + 3] = 255;
      }
    }
  }
  return pixels;
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
  let canvas: ReturnType<typeof stubCanvas>;

  beforeEach(() => {
    installDialogPolyfill();
    canvas = stubCanvas();
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
      relayUrl: 'wss://relay.example.com',
      relayUrls: ['wss://relay.primal.net', 'wss://relay.example.com'],
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
      'wss://relay.example.com',
    ]);
    expect(uriText.value).toContain('name=Canary');

    await settleMicrotasks();
    expect(createBunkerSignerFromNostrConnect).toHaveBeenCalledWith(expect.objectContaining({
      uri: uriText.value,
      abortSignal: expect.any(AbortSignal),
    }));
    // The QR is our own encoder's output: error correction L, two-module quiet zone,
    // light background, and a real decoder reads the same URI back from the pixels.
    const expected = encode(uriText.value, { ecc: 'L' });
    const side = expected.size + 4;
    const [background, firstDark] = [canvas.rects[0], canvas.rects[1]];
    expect(background).toEqual({ x: 0, y: 0, w: 360, h: 360, fill: '#ffffff' });
    expect(firstDark.fill).toBe('#0a0418');
    expect(firstDark.x).toBe(Math.round((2 * 360) / side));
    expect(firstDark.y).toBe(Math.round((2 * 360) / side));
    const decoded = jsQR(rasterise(canvas.rects, 360), 360, 360);
    expect(decoded?.data).toBe(uriText.value);

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
      relayUrl: 'wss://relay.example.com',
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
      relays: ['wss://relay.example.com'],
      relay: 'wss://relay.example.com',
    });

    const status = await waitForElement<HTMLElement>('#signet-login-nc-status');
    expect(status.textContent).toContain('Connected to relay wss://relay.example.com');
    expect(events).toEqual([
      expect.objectContaining({
        type: 'relay-connected',
        relay: 'wss://relay.example.com',
      }),
    ]);

    document.querySelector<HTMLButtonElement>('[data-action="back"]')?.click();
    await expect(pending).resolves.toBeNull();
  });
});
