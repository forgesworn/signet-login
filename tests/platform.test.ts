/**
 * Unit coverage for phone-class platform detection.
 *
 * The login picker leads with whichever signer lives on the *other* device, so
 * it needs to know whether the current browser is a phone. iPadOS deliberately
 * counts as desktop (it reports as desktop Safari and its large screen suits the
 * other-device-first layout), and an unknown platform defaults to not-mobile.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { isMobile } from '../src/platform.js';

function setUserAgent(value: string): void {
  Object.defineProperty(window.navigator, 'userAgent', { configurable: true, value });
}

function setUserAgentData(value: unknown): void {
  Object.defineProperty(window.navigator, 'userAgentData', { configurable: true, value });
}

describe('isMobile', () => {
  afterEach(() => {
    setUserAgent('Mozilla/5.0');
    setUserAgentData(undefined);
  });

  it('treats an iPhone user agent as mobile', () => {
    setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1');
    expect(isMobile()).toBe(true);
  });

  it('treats an Android phone user agent as mobile', () => {
    setUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36');
    expect(isMobile()).toBe(true);
  });

  it('treats an Android tablet (no "Mobile" token) as not mobile', () => {
    setUserAgent('Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    expect(isMobile()).toBe(false);
  });

  it('treats a desktop Chrome user agent as not mobile', () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    expect(isMobile()).toBe(false);
  });

  it('treats iPadOS (reports as desktop Safari) as not mobile', () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15');
    expect(isMobile()).toBe(false);
  });

  it('prefers navigator.userAgentData.mobile when the client hint is present', () => {
    // Desktop-looking UA, but Client Hints authoritatively report mobile.
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    setUserAgentData({ mobile: true });
    expect(isMobile()).toBe(true);
  });

  it('honours userAgentData.mobile=false even when the UA string looks mobile', () => {
    setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)');
    setUserAgentData({ mobile: false });
    expect(isMobile()).toBe(false);
  });
});
