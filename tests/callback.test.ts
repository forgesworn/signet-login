import { afterEach, describe, expect, it, vi } from 'vitest';

import { handleCallback } from '../src/callback.js';

function installOpener(postMessage: ReturnType<typeof vi.fn>): void {
  Object.defineProperty(window, 'opener', {
    configurable: true,
    value: { postMessage },
  });
}

function setReferrer(referrer: string): void {
  Object.defineProperty(document, 'referrer', { configurable: true, value: referrer });
}

describe('handleCallback', () => {
  afterEach(() => {
    Object.defineProperty(window, 'opener', { configurable: true, value: null });
    setReferrer('');
    vi.restoreAllMocks();
    window.history.replaceState({}, '', '/');
  });

  it('posts callback params to the configured target origin', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    window.history.replaceState({}, '', '/?pubkey=abc&eventId=def');

    const result = handleCallback({
      closeAfterPost: false,
      targetOrigin: 'https://app.example',
    });

    expect(result).toEqual({
      isPopup: true,
      posted: true,
      params: { pubkey: 'abc', eventId: 'def' },
    });
    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { pubkey: 'abc', eventId: 'def' } },
      'https://app.example',
    );
  });

  it('withholds the post when no target origin can be determined', () => {
    // These params identify the user and can carry a live bunker credential,
    // so an undetermined opener must get nothing rather than a `*` broadcast.
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(window, 'close').mockImplementation(() => undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('');

    const result = handleCallback();

    expect(postMessage).not.toHaveBeenCalled();
    expect(result.posted).toBe(false);
    // The caller still gets the params — only the cross-origin hand-off is cut.
    expect(result.params).toEqual({ error: 'denied' });
    // Closing here would hide the reason the opener never heard back.
    expect(window.close).not.toHaveBeenCalled();
    expect(console.warn).toHaveBeenCalled();
  });

  it('broadcasts to the wildcard only when the caller asks for it explicitly', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('');

    handleCallback({ closeAfterPost: false, targetOrigin: '*' });

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { error: 'denied' } },
      '*',
    );
  });

  it('prefers the opener origin derived from document.referrer over the wildcard when no explicit targetOrigin is given', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(window, 'close').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('https://app.example/login?foo=bar');

    handleCallback();

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { error: 'denied' } },
      'https://app.example',
    );
  });

  it('still honours an explicit targetOrigin over a derivable referrer', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    window.history.replaceState({}, '', '/?pubkey=abc&eventId=def');
    setReferrer('https://attacker.example/');

    handleCallback({ closeAfterPost: false, targetOrigin: 'https://app.example' });

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { pubkey: 'abc', eventId: 'def' } },
      'https://app.example',
    );
  });

  it('withholds the post when document.referrer is present but unparseable', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('not-a-valid-url');

    expect(handleCallback({ closeAfterPost: false }).posted).toBe(false);
    expect(postMessage).not.toHaveBeenCalled();
  });

  it('withholds the post when the referrer yields an opaque origin', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('about:blank');

    expect(handleCallback({ closeAfterPost: false }).posted).toBe(false);
    expect(postMessage).not.toHaveBeenCalled();
  });
});
