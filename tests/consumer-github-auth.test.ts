import { describe, expect, it } from 'vitest';
// @ts-expect-error - plain .mjs helper shared with release tooling
import { createConsumerTokenResolver } from '../tools/consumer-github-auth.mjs';

describe('consumer GitHub credentials', () => {
  it('routes each request to its owner installation, including mixed-case owners', () => {
    const tokenFor = createConsumerTokenResolver({
      SIGNET_GH_TOKEN_FORGESWORN: 'forge-token',
      SIGNET_GH_TOKEN_THECRYPTODONKEY: 'donkey-token',
      SIGNET_GH_TOKEN_DECENTED: 'decented-token',
    });
    expect(tokenFor('https://api.github.com/repos/forgesworn/signet-app/actions/workflows/signet-compatibility.yml/dispatches')).toBe('forge-token');
    expect(tokenFor('/repos/TheCryptoDonkey/pallasite/actions/runs/123')).toBe('donkey-token');
    expect(tokenFor('/repos/decented/axenstax/actions/runs/456/jobs')).toBe('decented-token');
  });

  it('fails closed when an installation token is missing despite a broad fallback', () => {
    const tokenFor = createConsumerTokenResolver({ SIGNET_GH_TOKEN_FORGESWORN: 'forge-token', GH_TOKEN: 'broad-token' });
    expect(() => tokenFor('/repos/decented/axenstax/actions/runs/456')).toThrow('SIGNET_GH_TOKEN_DECENTED is required');
  });

  it('allows the existing operator CLI token when no installation tokens are supplied', () => {
    for (const env of [{ GH_TOKEN: 'operator-token' }, { GITHUB_TOKEN: 'operator-token' }]) {
      expect(createConsumerTokenResolver(env)('/repos/forgesworn/signet-app/actions/runs/123')).toBe('operator-token');
    }
  });

  it('rejects requests that could leak tokens or reach an unrelated API', () => {
    const tokenFor = createConsumerTokenResolver({ GH_TOKEN: 'secret' });
    for (const path of [
      'https://example.com/repos/forgesworn/signet-app/actions/runs/123',
      '//example.com/repos/forgesworn/signet-app/actions/runs/123',
      'http://api.github.com/repos/forgesworn/signet-app/actions/runs/123',
      'https://user@api.github.com/repos/forgesworn/signet-app/actions/runs/123',
      '/repos/unrelated/project/actions/runs/123',
      '/repos/forgesworn/signet-app/contents/README.md',
    ]) expect(() => tokenFor(path)).toThrow('Refusing to send');
  });

  it('reports missing credentials without including values in the error', () => {
    expect(() => createConsumerTokenResolver({})('/repos/forgesworn/signet-app/actions/runs/123')).toThrow('GH_TOKEN or GITHUB_TOKEN is required');
  });
});
