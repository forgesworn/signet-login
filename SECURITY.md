# Security policy

## Reporting a vulnerability

Security issues should be reported via
[GitHub Security Advisories](https://github.com/forgesworn/signet-login/security/advisories/new)
at this repo. Do not use the public issue tracker for security reports.

You should receive an initial response within 72 hours. Confirmed
issues will be prioritised over feature work and released as patch
versions.

## Supported versions

Only the latest release receives security fixes. While the package is
pre-1.0, minor bumps may carry breaking changes; pin a version and read
the changelog before upgrading.

## What this SDK does and does not do for you

`signet-login` proves *which key* signed a login and binds that proof to
your origin. Three things it cannot do on your behalf, each of which has
caused real integration bugs:

- **The challenge must come from your server and be single-use.**
  `verifyLogin` is stateless, so within its freshness window a replayed
  auth event verifies exactly like the original. `login()` will
  auto-generate a challenge when you omit one — correct for an app with
  no backend, but a server that accepts a browser-chosen challenge has no
  replay protection at all. See
  [The challenge must be yours, and single-use](README.md#the-challenge-must-be-yours-and-single-use).

- **The auth event must be verified server-side.** A session object in
  the browser is not an authentication decision. See
  [Server-side verification](README.md#server-side-verification).

- **Callback params must be posted to a known origin.** They identify the
  user and can carry a live `bunker://...?secret=...` NIP-46 credential,
  so always pass `targetOrigin` to `handleCallback`. See
  [`Signet.handleCallback`](README.md#signethandlecallbackopts).

Also worth knowing: bunker reconnect data lives in `localStorage`, and the
persistent client key deliberately survives logout so signers keep
auto-approving. XSS on your origin therefore yields a durable signing bond
rather than a session you can revoke by logging out — pair this SDK with a
strict CSP, and use a custom encrypted storage adapter if that is in your
threat model. See [Storage](README.md#storage).
