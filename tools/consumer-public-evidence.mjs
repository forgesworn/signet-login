import { readFileSync } from 'node:fs';

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// These are reviewed workflow blobs, never values supplied by a release input.
export const PUBLIC_CONTRACTS = freeze(JSON.parse(readFileSync(new URL('./consumer-public-contracts.json', import.meta.url), 'utf8')));
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;
function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}
function keys(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

export function parsePublicEvidence(json, expectedVersion) {
  let input;
  try {
    if (typeof json !== 'string' || json.length > 32_000) throw new Error();
    input = JSON.parse(json);
  } catch {
    throw new Error('Invalid public consumer evidence JSON');
  }
  const invalid = 'Invalid public consumer evidence manifest';
  requireThat(keys(input, ['version', 'candidateSha', 'candidateVersion', 'requestId', 'sdkCI', 'runs']), invalid);
  requireThat(input.version === 1 && sha(input.candidateSha), invalid);
  requireThat(typeof input.candidateVersion === 'string' && /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(input.candidateVersion)
    && input.candidateVersion === expectedVersion, invalid);
  requireThat(typeof input.requestId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{15,99}$/.test(input.requestId), invalid);
  requireThat(keys(input.sdkCI, ['runId', 'attempt']) && positive(input.sdkCI.runId) && positive(input.sdkCI.attempt), invalid);
  requireThat(Array.isArray(input.runs) && input.runs.length === PUBLIC_CONTRACTS.consumers.length, invalid);
  const repos = new Set(PUBLIC_CONTRACTS.consumers.map(contract => contract.repo));
  for (const run of input.runs) {
    requireThat(keys(run, ['repo', 'runId', 'attempt', 'headSha']) && repos.delete(run.repo)
      && positive(run.runId) && positive(run.attempt) && sha(run.headSha), invalid);
  }
  requireThat(repos.size === 0, invalid);
  return freeze(input);
}

function realSuccess(value) {
  return value?.status === 'completed' && value.conclusion === 'success'
    && typeof value.started_at === 'string' && Number.isFinite(Date.parse(value.started_at))
    && typeof value.completed_at === 'string' && Number.isFinite(Date.parse(value.completed_at))
    && Date.parse(value.completed_at) >= Date.parse(value.started_at);
}

export async function verifyPublicEvidence(value, { readJson, expectedVersion }) {
  const input = parsePublicEvidence(JSON.stringify(value), expectedVersion);
  const selections = [
    { contract: PUBLIC_CONTRACTS.sdkCI, selected: { ...input.sdkCI, headSha: input.candidateSha }, sdk: true },
    ...PUBLIC_CONTRACTS.consumers.map(contract => ({ contract, selected: input.runs.find(run => run.repo === contract.repo), sdk: false })),
  ];
  async function checkRun({ contract, selected, sdk }) {
    const run = await readJson(`/repos/${contract.repo}/actions/runs/${selected.runId}`);
    const prefix = contract.kind === 'ecosystem' ? 'Signet ecosystem' : 'Signet compatibility';
    requireThat(run?.id === selected.runId && run.repository?.full_name === contract.repo
      && run.head_sha === selected.headSha && run.head_branch === 'main' && run.path === contract.workflowPath
      && run.event === (sdk ? 'push' : 'workflow_dispatch') && run.run_attempt === selected.attempt
      && run.status === 'completed' && run.conclusion === 'success'
      && (sdk || run.display_title === `${prefix} sha=${input.candidateSha} version=${input.candidateVersion} request=${input.requestId}`),
    `Public run does not satisfy the reviewed contract: ${contract.repo}`);
    if (!sdk) {
      const main = await readJson(`/repos/${contract.repo}/git/ref/heads/main`);
      requireThat(main?.object?.sha === selected.headSha, `Consumer main changed: ${contract.repo}`);
    }
    return run;
  }
  const proofs = [];
  for (const selection of selections) {
    const { contract, selected } = selection;
    await checkRun(selection);
    const workflow = await readJson(`/repos/${contract.repo}/contents/${contract.workflowPath}?ref=${selected.headSha}`);
    requireThat(workflow?.type === 'file' && workflow.path === contract.workflowPath && workflow.sha === contract.workflowBlobSha,
      `Workflow blob is not reviewed: ${contract.repo}`);
    const page = await readJson(`/repos/${contract.repo}/actions/runs/${selected.runId}/attempts/${selected.attempt}/jobs?per_page=100`);
    requireThat(Array.isArray(page?.jobs) && page.total_count === page.jobs.length && page.total_count <= 100,
      `Incomplete public job observation: ${contract.repo}`);
    const allowed = new Set([...contract.jobs.map(job => job.name), ...(contract.optionalJobs || [])]);
    const seen = new Set();
    for (const job of page.jobs) {
      requireThat(allowed.has(job.name) && !seen.has(job.name) && job.run_id === selected.runId
        && job.run_attempt === selected.attempt && job.head_sha === selected.headSha,
      `Unexpected public job: ${contract.repo}`);
      seen.add(job.name);
      if ((contract.optionalJobs || []).includes(job.name) && job.status === 'completed' && job.conclusion === 'skipped') continue;
      requireThat(realSuccess(job), `Public job did not run successfully: ${contract.repo}`);
      const required = contract.jobs.find(requiredJob => requiredJob.name === job.name);
      if (!required) continue;
      requireThat(Array.isArray(job.steps), `Missing public steps: ${contract.repo}`);
      for (const name of required.requiredSteps) {
        const matches = job.steps.filter(step => step.name === name);
        requireThat(matches.length === 1 && realSuccess(matches[0]), `Required public step did not run successfully: ${contract.repo}`);
      }
    }
    requireThat(contract.jobs.every(job => seen.has(job.name)), `Required public job is missing: ${contract.repo}`);
    proofs.push({ repo: contract.repo, kind: contract.kind || 'sdk-ci', ...selected, workflowBlobSha: workflow.sha });
  }
  // A rerun or a changed consumer branch invalidates the entire cohort.
  for (const selection of selections) await checkRun(selection);
  return freeze({ version: 1, candidateSha: input.candidateSha, candidateVersion: input.candidateVersion,
    requestId: input.requestId, sdkCI: proofs[0], consumers: proofs.slice(1) });
}

export const PUBLIC_PHYSICAL_SMOKE_PATH = '/repos/forgesworn/signet-app/actions/workflows/physical-mobile-smoke.yml/runs?branch=main&per_page=30&event=workflow_dispatch&status=success';

export const PRIVATE_CONSUMER_REPO = 'TheCryptoDonkey/forge-realms';

export function createPublicReader({ token, privateToken, fetchImpl = fetch } = {}) {
  const repos = [PUBLIC_CONTRACTS.sdkCI, ...PUBLIC_CONTRACTS.consumers].map(contract => contract.repo);
  return async path => {
    requireThat(typeof path === 'string' && (path === PUBLIC_PHYSICAL_SMOKE_PATH || (repos.some(repo => path.startsWith(`/repos/${repo}/`))
      && /^\/repos\/[A-Za-z0-9-]+\/[A-Za-z0-9-]+\/(?:actions\/runs\/[1-9]\d*(?:\/attempts\/[1-9]\d*\/jobs\?per_page=100)?|contents\/\.github\/workflows\/[a-z-]+\.yml\?ref=[a-f0-9]{40}|git\/ref\/heads\/main)$/.test(path))),
    'Unsupported public evidence API path');
    const privateRepo = path.startsWith(`/repos/${PRIVATE_CONSUMER_REPO}/`);
    requireThat(!privateRepo || (typeof privateToken === 'string' && privateToken.length > 0),
      'A scoped read token is required for the private Forge Realms evidence');
    const credential = privateRepo ? privateToken : path.startsWith(`/repos/${PUBLIC_CONTRACTS.sdkCI.repo}/`) ? token : undefined;
    const response = await fetchImpl(`https://api.github.com${path}`, {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        // The workflow token is scoped to this SDK repository. Downstream
        // public evidence needs no credential. Private Forge Realms evidence uses
        // its separate, repository-scoped read token and never a fallback.
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}) },
    });
    requireThat(response.status === 200, `Public GitHub evidence observation failed: HTTP ${response.status} at ${path}`);
    const body = await response.text();
    requireThat(body.length <= 2_000_000, 'Public GitHub evidence response is too large');
    try { return JSON.parse(body); } catch { throw new Error('Invalid public GitHub evidence response'); }
  };
}
