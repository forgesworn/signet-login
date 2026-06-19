#!/usr/bin/env node
import { randomUUID } from 'node:crypto';

const dryRun = process.argv.includes('--dry-run');
const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';
const requestId = process.env.SIGNET_COMPATIBILITY_REQUEST_ID || randomUUID();
const signetLoginRef = process.env.SIGNET_LOGIN_REF || process.env.GITHUB_REF_NAME || 'local';
const signetLoginSha = process.env.SIGNET_LOGIN_SHA || process.env.GITHUB_SHA || '';
const timeoutMinutes = Number(process.env.CONSUMER_COMPATIBILITY_TIMEOUT_MINUTES || '45');
const physicalSmokeMaxAgeDays = Number(process.env.PHYSICAL_MOBILE_SMOKE_MAX_AGE_DAYS || '7');

const consumers = [
  {
    name: 'Canary',
    repo: 'forgesworn/canary-kit',
    workflow: 'signet-compatibility.yml',
    ref: 'main',
  },
  {
    name: 'MySignet',
    repo: 'forgesworn/signet-app',
    workflow: 'signet-compatibility.yml',
    ref: 'main',
  },
  {
    name: 'Pallasite',
    repo: 'TheCryptoDonkey/pallasite',
    workflow: 'signet-compatibility.yml',
    ref: 'main',
  },
  {
    name: 'Axenstax',
    repo: 'decented/axenstax',
    workflow: 'signet-compatibility.yml',
    ref: 'main',
  },
  {
    name: 'Forge Realms',
    repo: 'TheCryptoDonkey/forge-realms',
    workflow: 'ci.yml',
    ref: 'main',
    inputs: {
      run_soak: 'false',
      soak_seconds: '32',
    },
  },
];

const physicalMobileSmoke = {
  name: 'MySignet physical mobile smoke',
  repo: 'forgesworn/signet-app',
  workflow: 'physical-mobile-smoke.yml',
  ref: 'main',
};

function log(message) {
  console.log(`[signet-compat] ${message}`);
}

function fail(message) {
  console.error(`[signet-compat] ${message}`);
  process.exit(1);
}

function workflowUrl(repo, workflow, suffix = '') {
  return `https://api.github.com/repos/${repo}/actions/workflows/${encodeURIComponent(workflow)}${suffix}`;
}

async function github(path, options = {}) {
  if (!token) fail('GH_TOKEN or GITHUB_TOKEN is required unless --dry-run is used.');

  const res = await fetch(path.startsWith('https://') ? path : `https://api.github.com${path}`, {
    ...options,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      ...(options.headers || {}),
    },
  });

  if (res.status === 204) return null;

  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  if (!res.ok) {
    const detail = typeof body === 'string' ? body : body?.message ?? res.statusText;
    throw new Error(`${res.status} ${res.statusText}: ${detail}`);
  }

  return body;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function listRuns(consumer, params = {}) {
  const query = new URLSearchParams({
    branch: consumer.ref,
    per_page: '30',
    ...params,
  });
  return await github(workflowUrl(consumer.repo, consumer.workflow, `/runs?${query.toString()}`));
}

async function dispatchConsumer(consumer) {
  const before = await listRuns(consumer, { event: 'workflow_dispatch' });
  const beforeIds = new Set((before.workflow_runs || []).map(run => run.id));
  const startedAt = new Date();
  const inputs = {
    ...(consumer.inputs || {}),
    signet_login_ref: signetLoginRef,
    signet_login_sha: signetLoginSha,
    request_id: requestId,
  };

  log(`dispatching ${consumer.name} (${consumer.repo}/${consumer.workflow})`);
  await github(workflowUrl(consumer.repo, consumer.workflow, '/dispatches'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref: consumer.ref, inputs }),
  });

  return { consumer, beforeIds, startedAt };
}

async function findDispatchedRun(dispatch) {
  const deadline = Date.now() + 2 * 60_000;
  while (Date.now() < deadline) {
    const runs = await listRuns(dispatch.consumer, { event: 'workflow_dispatch' });
    const match = (runs.workflow_runs || [])
      .filter(run => !dispatch.beforeIds.has(run.id))
      .filter(run => new Date(run.created_at).getTime() >= dispatch.startedAt.getTime() - 60_000)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0];

    if (match) return match;
    await sleep(5_000);
  }
  throw new Error(`${dispatch.consumer.name}: dispatched workflow run did not appear within 2 minutes`);
}

async function waitForRun(consumer, run) {
  const deadline = Date.now() + timeoutMinutes * 60_000;
  let current = run;

  while (Date.now() < deadline) {
    current = await github(`/repos/${consumer.repo}/actions/runs/${current.id}`);
    if (current.status === 'completed') {
      if (current.conclusion === 'success') {
        log(`${consumer.name} passed: ${current.html_url}`);
        return current;
      }
      throw new Error(`${consumer.name} failed with conclusion ${current.conclusion}: ${current.html_url}`);
    }

    log(`${consumer.name} still ${current.status}: ${current.html_url}`);
    await sleep(15_000);
  }

  throw new Error(`${consumer.name}: run timed out after ${timeoutMinutes} minutes: ${current.html_url}`);
}

async function checkRecentPhysicalMobileSmoke() {
  const runs = await listRuns(physicalMobileSmoke, {
    event: 'workflow_dispatch',
    status: 'success',
  });
  const successfulRuns = (runs.workflow_runs || [])
    .filter(run => run.conclusion === 'success')
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const latest = successfulRuns[0];
  if (!latest) {
    throw new Error(`${physicalMobileSmoke.name}: no successful run found. Run ${physicalMobileSmoke.workflow} before publishing Signet.`);
  }

  const ageMs = Date.now() - new Date(latest.created_at).getTime();
  const maxAgeMs = physicalSmokeMaxAgeDays * 24 * 60 * 60 * 1000;
  if (ageMs > maxAgeMs) {
    throw new Error(`${physicalMobileSmoke.name}: latest success is older than ${physicalSmokeMaxAgeDays} days (${latest.html_url}).`);
  }

  log(`${physicalMobileSmoke.name} is recent enough: ${latest.html_url}`);
}

function printDryRun() {
  log('dry run only; no GitHub workflows will be dispatched.');
  log(`request_id=${requestId}`);
  log(`signet_login_ref=${signetLoginRef}`);
  log(`signet_login_sha=${signetLoginSha || '<empty>'}`);
  log(`physical smoke max age: ${physicalSmokeMaxAgeDays} day(s)`);
  log(`consumer timeout: ${timeoutMinutes} minute(s)`);
  for (const consumer of consumers) {
    const inputs = {
      ...(consumer.inputs || {}),
      signet_login_ref: signetLoginRef,
      signet_login_sha: signetLoginSha,
      request_id: requestId,
    };
    log(`${consumer.name}: ${consumer.repo}/${consumer.workflow}@${consumer.ref} inputs=${JSON.stringify(inputs)}`);
  }
  log(`${physicalMobileSmoke.name}: ${physicalMobileSmoke.repo}/${physicalMobileSmoke.workflow}@${physicalMobileSmoke.ref}`);
}

async function main() {
  if (dryRun) {
    printDryRun();
    return;
  }

  await checkRecentPhysicalMobileSmoke();

  const dispatches = [];
  for (const consumer of consumers) {
    dispatches.push(await dispatchConsumer(consumer));
  }

  const runs = await Promise.all(dispatches.map(async dispatch => ({
    consumer: dispatch.consumer,
    run: await findDispatchedRun(dispatch),
  })));

  await Promise.all(runs.map(({ consumer, run }) => waitForRun(consumer, run)));
  log('all consumer compatibility workflows passed.');
}

main().catch(err => {
  fail(err instanceof Error ? err.message : String(err));
});
