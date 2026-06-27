import { afterEach, describe, expect, it, vi } from 'vitest';

import { handleCallback } from '../src/callback.js';

function installOpener(postMessage: ReturnType<typeof vi.fn>): void {
  Object.defineProperty(window, 'opener', {
    configurable: true,
    value: { postMessage },
  });
}

describe('handleCallback', () => {
  afterEach(() => {
    Object.defineProperty(window, 'opener', { configurable: true, value: null });
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

  it('keeps wildcard postMessage target by default for compatibility', () => {
    const postMessage = vi.fn();
    installOpener(postMessage);
    vi.spyOn(window, 'close').mockImplementation(() => undefined);
    window.history.replaceState({}, '', '/?error=denied');

    handleCallback();

    expect(postMessage).toHaveBeenCalledWith(
      { type: 'signet-login-callback', params: { error: 'denied' } },
      '*',
    );
    expect(window.close).toHaveBeenCalled();
  });
});
