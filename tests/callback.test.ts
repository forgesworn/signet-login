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
      params: { pubkey: 'abc', eventId: 'def' },
    });
    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { pubkey: 'abc', eventId: 'def' } },
      'https://app.example',
    );
  });

  it('keeps wildcard postMessage target by default when no referrer is available', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(window, 'close').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('');

    handleCallback();

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { error: 'denied' } },
      '*',
    );
    expect(window.close).toHaveBeenCalled();
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

  it('falls back to the wildcard when document.referrer is present but unparseable', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    window.history.replaceState({}, '', '/?error=denied');
    setReferrer('not-a-valid-url');

    handleCallback({ closeAfterPost: false });

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { error: 'denied' } },
      '*',
    );
  });
});
