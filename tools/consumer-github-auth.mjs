const ownerVariables = {
  forgesworn: 'SIGNET_GH_TOKEN_FORGESWORN',
  thecryptodonkey: 'SIGNET_GH_TOKEN_THECRYPTODONKEY',
  decented: 'SIGNET_GH_TOKEN_DECENTED',
};

/** Select an installation token without forwarding it outside GitHub Actions APIs. */
export function createConsumerTokenResolver(env) {
  const scoped = Object.values(ownerVariables).some(name => Boolean(env[name]));
  return path => {
    const url = new URL(path, 'https://api.github.com');
    const owner = /^\/repos\/([^/]+)\/[^/]+\/actions\//.exec(url.pathname)?.[1]?.toLowerCase();
    if (url.origin !== 'https://api.github.com' || url.username || url.password || !Object.hasOwn(ownerVariables, owner)) {
      throw new Error('Refusing to send a consumer credential outside the configured GitHub Actions APIs.');
    }
    const variable = ownerVariables[owner];
    // Once installation tokens are supplied, never fall back to a broader token.
    const token = scoped ? env[variable] : env.GH_TOKEN || env.GITHUB_TOKEN;
    if (!token) {
      throw new Error(scoped ? `${variable} is required for this consumer owner.` : 'GH_TOKEN or GITHUB_TOKEN is required unless --dry-run is used.');
    }
    return token;
  };
}
