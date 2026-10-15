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

## Reusing completed compatibility runs

When an App installation is unavailable, an authorised operator can dispatch the
same six workflows using the existing local CLI credential. Publication can then
use the release workflow's optional `consumer_runs` JSON input. This path makes
read-only GitHub API requests. The workflow token authenticates only reads of
signet-login itself; the five public consumers are read anonymously, including
the configured physical smoke check. Forge Realms is private: the existing
TheCryptoDonkey App installation must grant **Actions: read** and **Contents:
read** for its evidence. The reuse job mints a token for **forge-realms only**
with those read permissions; it neither dispatches nor writes there. The App's
permission settings must allow Contents read and that installation must accept
the addition before this path can run. Other installations need no access change
for reuse. No stored PAT or new decented installation is needed. Public API rate
limits or unreadable evidence fail the gate; there is no fallback to accepting
an unverified run or forwarding a different credential. Omitting the input
retains the App dispatch path.
Invalid evidence fails the release without falling back to dispatch.

The input has this shape (supply all six repositories from
`tools/consumer-public-contracts.json` exactly once):

```json
{
  "version": 1,
  "candidateSha": "<full tested SDK commit SHA>",
  "candidateVersion": "<package.json version>",
  "requestId": "<common request ID of 16 to 100 safe characters>",
  "sdkCI": { "runId": 123, "attempt": 1 },
  "runs": [
    {
      "repo": "forgesworn/canary-kit",
      "runId": 456,
      "attempt": 1,
      "headSha": "<full consumer main commit SHA>"
    }
  ]
}
```

Every consumer run must be a successful, completed `workflow_dispatch` attempt
on its current `main`. The five SDK workflows publish the effective SDK checkout
SHA, package version and request ID in their run title. Forge Realms remains an
ecosystem regression check: its title identifies the cohort, but it does not
install the SDK candidate. Public titles alone are insufficient: the verifier
also pins each historical workflow blob and requires its real successful jobs
and named build, installation and regression steps. Never-started runs and
skipped required steps fail. Only Forge Realms' optional soak may be skipped.
All run attempts and consumer main heads are read again before returning success.

The candidate's main-push SDK CI must pass both Node 22 and 24 with the reviewed CI
workflow. The release commit must descend from that tested candidate and may
change only the specific release tools, tests, documentation and release workflow
listed in `tools/consumer-release-payload.mjs`. Its built npm tarball must contain
exactly the same regular file names and bytes as the candidate's committed
package payload. Runtime, dependency, package configuration and build changes
require a new candidate and fresh consumer runs. The local verifier requires
Git and Python 3 as well as Node; Ubuntu release runners already provide these.

The configured physical mobile smoke requirement applies before either release
path. This mechanism adds no physical-device acceptance claim. The downstream
Anvil publisher and its OIDC configuration are unchanged, and still depend on
the compatibility job. Both package checkouts use the explicitly requested release tag. For public reuse,
the compatibility job separately checks out only the verifier tools at
`github.workflow_sha`, the immutable commit containing the executing workflow.
The verifier runs from the tagged package's working directory and receives that
package's recorded version and commit; it cannot substitute its own package
version or build. This lets reviewed release-tool repairs run against an unchanged
release tag. Omitting public evidence retains the original tagged App-dispatch
checker. The workflow logs the verifier commit separately from the package commit.
After Anvil's independent build and full tests, its test command also packs the
current build and checks all package file names and bytes against that tagged
Git source and the compatibility job's validated candidate commit. It also
requires the publisher checkout to equal the compatibility job's release commit;
a tag moving between those checkouts fails. Only validated full commit SHAs are
passed to the publisher command. Shallow publisher checkouts fetch ancestry for
the same commit before applying the candidate-to-release source diff restriction.
Distribution drift fails before Anvil records its canonical tarball.
Anvil then applies its existing independent-build reproducibility gate and
publishes the recorded tarball.
