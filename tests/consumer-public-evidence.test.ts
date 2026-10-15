// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { PUBLIC_CONTRACTS, PUBLIC_PHYSICAL_SMOKE_PATH, PRIVATE_CONSUMER_REPO, createPublicReader, parsePublicEvidence, verifyPublicEvidence } from '../tools/consumer-public-evidence.mjs';

const candidateSha = 'a'.repeat(40), candidateVersion = '0.18.2', requestId = 'vennel-sdk-0123456789abcdef';
const started = '2026-10-15T00:00:00Z', completed = '2026-10-15T00:01:00Z';
function fixture() {
  const input = { version: 1, candidateSha, candidateVersion, requestId, sdkCI: { runId: 100, attempt: 1 },
    runs: PUBLIC_CONTRACTS.consumers.map((contract: any, index: number) => ({ repo: contract.repo, runId: 200 + index, attempt: 1, headSha: String(index + 1).repeat(40) })) };
  const values = new Map<string, any>();
  for (const [index, contract] of [PUBLIC_CONTRACTS.sdkCI, ...PUBLIC_CONTRACTS.consumers].entries()) {
    const selected = index === 0 ? { ...input.sdkCI, headSha: candidateSha } : input.runs[index - 1];
    const runPath = `/repos/${contract.repo}/actions/runs/${selected.runId}`;
    values.set(runPath, { id: selected.runId, repository: { full_name: contract.repo }, event: index === 0 ? 'push' : 'workflow_dispatch',
      head_sha: selected.headSha, head_branch: 'main', run_attempt: selected.attempt, status: 'completed', conclusion: 'success', path: contract.workflowPath,
      display_title: `${contract.kind === 'ecosystem' ? 'Signet ecosystem' : 'Signet compatibility'} sha=${candidateSha} version=${candidateVersion} request=${requestId}` });
    values.set(`${runPath}/attempts/1/jobs?per_page=100`, { total_count: contract.jobs.length, jobs: contract.jobs.map((job: any) => ({
      name: job.name, run_id: selected.runId, run_attempt: 1, head_sha: selected.headSha, status: 'completed', conclusion: 'success', started_at: started, completed_at: completed,
      steps: job.requiredSteps.map((name: string, number: number) => ({ name, number: number + 1, status: 'completed', conclusion: 'success', started_at: started, completed_at: completed })) })) });
    values.set(`/repos/${contract.repo}/contents/${contract.workflowPath}?ref=${selected.headSha}`, { type: 'file', path: contract.workflowPath, sha: contract.workflowBlobSha });
    if (index !== 0) values.set(`/repos/${contract.repo}/git/ref/heads/main`, { object: { sha: selected.headSha } });
  }
  return { input, values, async readJson(path: string) { if (!values.has(path)) throw Error('Unexpected GitHub path: ' + path); return structuredClone(values.get(path)); } };
}

describe('public completed consumer evidence', () => {
  it('requires every real successful attempt and the candidate SDK CI, retaining the ecosystem boundary', async () => {
    const f = fixture();
    const proof = await verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion });
    expect(proof.candidateSha).toBe(candidateSha); expect(proof.consumers).toHaveLength(5);
    expect(proof.consumers.filter((run: any) => run.kind === 'sdk')).toHaveLength(4);
    expect(proof.consumers.find((run: any) => run.kind === 'ecosystem').repo).toBe('TheCryptoDonkey/forge-realms');
  });
  for (const defect of ['missing-consumer', 'duplicate-consumer', 'extra-consumer', 'wrong-repo', 'bad-attempt', 'bad-sha', 'bad-request', 'extra-field']) {
    it(`refuses a ${defect} manifest before reading GitHub`, () => {
      const f = fixture(), input: any = f.input;
      if (defect === 'missing-consumer') input.runs.pop();
      if (defect === 'duplicate-consumer') input.runs[1] = { ...input.runs[0] };
      if (defect === 'extra-consumer') input.runs.push({ ...input.runs[0] });
      if (defect === 'wrong-repo') input.runs[0].repo = 'attacker/canary-kit';
      if (defect === 'bad-attempt') input.runs[0].attempt = 0;
      if (defect === 'bad-sha') input.candidateSha = 'main';
      if (defect === 'bad-request') input.requestId = 'untracked';
      if (defect === 'extra-field') input.skip = true;
      expect(() => parsePublicEvidence(JSON.stringify(input), candidateVersion)).toThrow();
    });
  }
  it('does not echo malformed JSON or accept a different package version', () => {
    expect(() => parsePublicEvidence('secret-not-json', candidateVersion)).toThrow('Invalid public consumer evidence JSON');
    expect(() => parsePublicEvidence(JSON.stringify(fixture().input), '0.19.0')).toThrow();
  });
  for (const defect of ['failed-run', 'queued-run', 'wrong-workflow', 'wrong-event', 'wrong-head', 'wrong-branch', 'wrong-title-sha', 'wrong-title-version', 'wrong-title-cohort', 'wrong-attempt', 'wrong-workflow-blob', 'missing-jobs', 'skipped-job', 'skipped-candidate-step', 'missing-candidate-step', 'unstarted-step', 'incomplete-job-page', 'new-main-head']) {
    it(`refuses ${defect} evidence`, async () => {
      const f = fixture(), c = PUBLIC_CONTRACTS.consumers[0], row = f.input.runs[0];
      const run = f.values.get(`/repos/${c.repo}/actions/runs/${row.runId}`);
      const jobs = f.values.get(`/repos/${c.repo}/actions/runs/${row.runId}/attempts/1/jobs?per_page=100`);
      if (defect === 'failed-run') run.conclusion = 'failure';
      if (defect === 'queued-run') run.status = 'queued';
      if (defect === 'wrong-workflow') run.path = '.github/workflows/other.yml';
      if (defect === 'wrong-event') run.event = 'pull_request';
      if (defect === 'wrong-head') run.head_sha = 'f'.repeat(40);
      if (defect === 'wrong-branch') run.head_branch = 'unreviewed';
      if (defect === 'wrong-title-sha') run.display_title = run.display_title.replace(candidateSha, 'b'.repeat(40));
      if (defect === 'wrong-title-version') run.display_title = run.display_title.replace(candidateVersion, '0.19.0');
      if (defect === 'wrong-title-cohort') run.display_title = run.display_title.replace(requestId, 'different-cohort-0123456789');
      if (defect === 'wrong-attempt') run.run_attempt++;
      if (defect === 'wrong-workflow-blob') f.values.get(`/repos/${c.repo}/contents/${c.workflowPath}?ref=${row.headSha}`).sha = 'f'.repeat(40);
      if (defect === 'missing-jobs') { jobs.jobs = []; jobs.total_count = 0; }
      if (defect === 'skipped-job') jobs.jobs[0].conclusion = 'skipped';
      if (defect === 'skipped-candidate-step') jobs.jobs[0].steps[0].conclusion = 'skipped';
      if (defect === 'missing-candidate-step') jobs.jobs[0].steps.shift();
      if (defect === 'unstarted-step') jobs.jobs[0].steps[0].started_at = null;
      if (defect === 'incomplete-job-page') jobs.total_count++;
      if (defect === 'new-main-head') f.values.get(`/repos/${c.repo}/git/ref/heads/main`).object.sha = 'f'.repeat(40);
      await expect(verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion })).rejects.toThrow();
    });
  }
  it('rejects a later rerun even when the first observed attempt passed', async () => {
    const f = fixture(), path = `/repos/${f.input.runs[0].repo}/actions/runs/${f.input.runs[0].runId}`; let reads = 0;
    await expect(verifyPublicEvidence(f.input, { expectedVersion: candidateVersion, readJson: async (target: string) => {
      const value = await f.readJson(target); if (target === path && ++reads > 1) value.run_attempt++; return value;
    } })).rejects.toThrow();
  });
  it('refuses failed SDK source CI and GitHub observation failures', async () => {
    const f = fixture(); f.values.get('/repos/forgesworn/signet-login/actions/runs/100').conclusion = 'failure';
    await expect(verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion })).rejects.toThrow();
    await expect(verifyPublicEvidence(fixture().input, { readJson: async () => { throw Error('GitHub unavailable'); }, expectedVersion: candidateVersion })).rejects.toThrow('GitHub unavailable');
  });
  it('permits the explicitly optional skipped ecosystem soak but refuses extra or duplicated jobs', async () => {
    const f = fixture(), c = PUBLIC_CONTRACTS.consumers.find((row: any) => row.kind === 'ecosystem');
    const selected = f.input.runs.find(row => row.repo === c.repo)!;
    const page = f.values.get(`/repos/${c.repo}/actions/runs/${selected.runId}/attempts/1/jobs?per_page=100`);
    page.jobs.push({ ...page.jobs[0], name: 'Runtime Soak', conclusion: 'skipped', started_at: null, completed_at: null, steps: [] });
    page.total_count++;
    await expect(verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion })).resolves.toBeDefined();
    page.jobs[1].name = 'Unexpected gate';
    await expect(verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion })).rejects.toThrow();
    page.jobs[1].name = page.jobs[0].name;
    await expect(verifyPublicEvidence(f.input, { readJson: f.readJson, expectedVersion: candidateVersion })).rejects.toThrow();
  });
  it('rejects a later consumer main change after all initial observations passed', async () => {
    const f = fixture(), path = `/repos/${f.input.runs[0].repo}/git/ref/heads/main`; let reads = 0;
    await expect(verifyPublicEvidence(f.input, { expectedVersion: candidateVersion, readJson: async (target: string) => {
      const value = await f.readJson(target); if (target === path && ++reads > 1) value.object.sha = 'f'.repeat(40); return value;
    } })).rejects.toThrow();
  });
});

describe('public evidence transport', () => {
  it('uses only read-only GitHub API requests and refuses redirects', async () => {
    let observed: any;
    const readJson = createPublicReader({ token: 'test-token', fetchImpl: async (url: string, options: any) => {
      observed = { url, options }; return { status: 200, text: async () => '{"ok":true}' };
    } });
    await expect(readJson('/repos/forgesworn/canary-kit/actions/runs/123')).resolves.toEqual({ ok: true });
    expect(observed.url).toBe('https://api.github.com/repos/forgesworn/canary-kit/actions/runs/123');
    expect(observed.options.method).toBe('GET'); expect(observed.options.redirect).toBe('error');
    expect(observed.options.headers.Authorization).toBeUndefined();
  });
  it('uses the repository token only for SDK evidence, including every read needed by the full cohort', async () => {
    const f = fixture(), observed: Array<{ path: string; authenticated: boolean }> = [];
    const readJson = createPublicReader({ token: 'sdk-repository-token', privateToken: 'forge-read-token', fetchImpl: async (url: string, options: any) => {
      const path = new URL(url).pathname + new URL(url).search;
      const ownRepo = path.startsWith(`/repos/${PUBLIC_CONTRACTS.sdkCI.repo}/`);
      const privateRepo = path.startsWith(`/repos/${PRIVATE_CONSUMER_REPO}/`);
      const authenticated = Boolean(options.headers.Authorization);
      observed.push({ path, authenticated });
      // Reproduce a repository-scoped token: it cannot read other repos' Actions.
      if (options.headers.Authorization === 'Bearer sdk-repository-token' && !ownRepo) return { status: 403, text: async () => 'Resource not accessible by integration' };
      expect(options.headers.Authorization).toBe(ownRepo ? 'Bearer sdk-repository-token' : privateRepo ? 'Bearer forge-read-token' : undefined);
      return { status: 200, text: async () => JSON.stringify(await f.readJson(path)) };
    } });
    const proof = await verifyPublicEvidence(f.input, { expectedVersion: candidateVersion, readJson });
    expect(proof.consumers).toHaveLength(5);
    expect(observed.filter(row => row.authenticated)).toHaveLength(10);
    expect(observed.filter(row => !row.authenticated)).toHaveLength(24);
  });
  it('refuses private evidence without its scoped token, even when an SDK token exists', async () => {
    const readJson = createPublicReader({ token: 'sdk-repository-token', fetchImpl: async () => { throw Error('Must not fetch'); } });
    await expect(readJson(`/repos/${PRIVATE_CONSUMER_REPO}/actions/runs/123`)).rejects.toThrow('A scoped read token is required');
  });
  it('keeps the exact physical smoke read public and refuses any alternate workflow or query', async () => {
    const observed: any[] = [];
    const readJson = createPublicReader({ token: 'sdk-repository-token', fetchImpl: async (url: string, options: any) => {
      observed.push({ url, options }); return { status: 200, text: async () => '{"workflow_runs":[]}' };
    } });
    await expect(readJson(PUBLIC_PHYSICAL_SMOKE_PATH)).resolves.toEqual({ workflow_runs: [] });
    expect(observed[0].options.headers.Authorization).toBeUndefined();
    expect(observed[0].options.method).toBe('GET');
    for (const path of [PUBLIC_PHYSICAL_SMOKE_PATH.replace('signet-app', 'canary-kit'),
      PUBLIC_PHYSICAL_SMOKE_PATH.replace('status=success', 'status=failure'),
      PUBLIC_PHYSICAL_SMOKE_PATH.replace('physical-mobile-smoke.yml', 'ci.yml')]) {
      await expect(readJson(path)).rejects.toThrow('Unsupported public evidence API path');
    }
    expect(observed).toHaveLength(1);
  });
  it('reports the fixed API path and HTTP status without response bodies, credentials, retries or fallback', async () => {
    let calls = 0;
    const path = '/repos/forgesworn/signet-login/actions/runs/123';
    const readJson = createPublicReader({ token: 'private-token', fetchImpl: async () => {
      calls++; return { status: 403, text: async () => 'sensitive response body' };
    } });
    await expect(readJson(path)).rejects.toThrow(`Public GitHub evidence observation failed: HTTP 403 at ${path}`);
    expect(calls).toBe(1);
  });
  for (const path of ['https://attacker.invalid/', '//attacker.invalid/', '/repos/attacker/repo/actions/runs/123', '/repos/forgesworn/canary-kit/actions/workflows/ci.yml/dispatches', '/repos/forgesworn/canary-kit/../secret', '/repos/forgesworn/canary-kit/actions/runs/123?token=secret']) {
    it(`refuses unsupported paths without fetching: ${path}`, async () => {
      const readJson = createPublicReader({ fetchImpl: async () => { throw Error('Must not fetch'); } });
      await expect(readJson(path)).rejects.toThrow('Unsupported public evidence API path');
    });
  }
  it('does not expose error response bodies and rejects malformed or oversized responses', async () => {
    const path = '/repos/forgesworn/canary-kit/actions/runs/123';
    for (const [status, body] of [[403, 'secret'], [302, 'secret'], [200, 'secret'], [200, 'x'.repeat(2_000_001)]]) {
      const readJson = createPublicReader({ fetchImpl: async () => ({ status, text: async () => body }) });
      await expect(readJson(path)).rejects.toThrow();
      try { await readJson(path); } catch (error) { expect(String(error)).not.toContain('secret'); }
    }
  });
});
