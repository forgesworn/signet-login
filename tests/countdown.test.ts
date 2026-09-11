import { describe, it, expect } from 'vitest';
import { expiresAtFor, remainingSeconds, formatRemaining } from '../src/countdown.js';

describe('expiresAtFor', () => {
  it('is five minutes after issuance', () => {
    expect(expiresAtFor(1_700_000_000)).toBe(1_700_000_300);
  });
});

describe('remainingSeconds', () => {
  it('counts down from the anchor, not from now', () => {
    // The discipline that matters: anchored to issuance, so backgrounding the
    // page does not reset the countdown.
    const issuedAt = 1_700_000_000;
    expect(remainingSeconds(issuedAt, 1_700_000_060)).toBe(240);
  });

  it('clamps at zero rather than going negative', () => {
    expect(remainingSeconds(1_700_000_000, 1_700_000_999)).toBe(0);
  });

  it('is the full window at the instant of issuance', () => {
    expect(remainingSeconds(1_700_000_000, 1_700_000_000)).toBe(300);
  });
});

describe('formatRemaining', () => {
  it('renders M:SS', () => {
    expect(formatRemaining(300)).toBe('5:00');
    expect(formatRemaining(252)).toBe('4:12');
    expect(formatRemaining(61)).toBe('1:01');
    expect(formatRemaining(9)).toBe('0:09');
    expect(formatRemaining(0)).toBe('0:00');
  });

  it('never renders a negative time', () => {
    expect(formatRemaining(-30)).toBe('0:00');
  });
});
