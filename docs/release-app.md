# Consumer compatibility release credentials

The release workflow uses the ForgeSworn Signet Releases GitHub App to dispatch
and read compatibility runs. Install it with **Actions: read and write** and the
mandatory **Metadata: read** permission on only these repositories:

| Account | Repositories |
| --- | --- |
| forgesworn | canary-kit, signet-app, signet-lite |
| TheCryptoDonkey | pallasite, forge-realms |
| decented | axenstax |

The App must allow installation on any account because the consumers span three
owners. It needs no webhook, OAuth user authorisation, Contents write, or Workflows
write permission. This does not change the visibility of any repository.

Configure `SIGNET_RELEASE_APP_CLIENT_ID` as a repository Actions variable and
`SIGNET_RELEASE_APP_PRIVATE_KEY` as a repository Actions secret in signet-login.
Back up the App metadata and private key in the operator's credential vault.
Never commit the key or put it in workflow logs.

Each release creates three installation tokens, scoped to the listed repositories
and Actions permission. The token action masks them and revokes them when the job
ends. The compatibility checker selects the token for the requested owner; when
any installation token is present, a missing owner token is an error, even if a
legacy CLI token is available. The App key is supplied only to the token actions.

Local operator runs still accept `GH_TOKEN` or `GITHUB_TOKEN` when no installation
tokens are supplied. The release workflow does not use `FORGESWORN_RELEASE_PAT`
or the shared source-read credential. npm publishing continues to use the Anvil
workflow's existing OIDC trusted publishing configuration.

See [GitHub's token action](https://github.com/actions/create-github-app-token)
for installation token lifetime and revocation behaviour.
