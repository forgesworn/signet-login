import { describe, it, expect } from 'vitest';
// @ts-expect-error - plain .mjs helper shared with tools/, no declarations
import { runNeverStarted } from '../tools/consumer-run-state.mjs';

/**
 * Both fixtures are the real /actions/runs/{id}/jobs payloads from
 * TheCryptoDonkey/forge-realms, trimmed to the fields the check reads.
 *
 * They are the two cases the release gate could not tell apart: a run that
 * failed on its merits, and a run that GitHub refused to start at all. Both
 * report conclusion "failure" at run level, so the run object alone is not
 * enough - the difference only shows up in whether any step ever executed.
 */

// Run 33236157803, 29 Aug: "The job was not started because an Actions budget
// is preventing further use." Nothing ran.
const budgetBlocked = [
  { name: 'Test, Build, Smoke', status: 'completed', conclusion: 'failure', steps: [] },
  { name: 'Runtime Soak', status: 'completed', conclusion: 'skipped', steps: [] },
];

// Run 29980733033, 23 Jul: check:signet-deps found a stale pin. Steps ran.
const meritFailure = [
  {
    name: 'Test, Build, Smoke',
    status: 'completed',
    conclusion: 'failure',
    steps: Array.from({ length: 14 }, (_, i) => ({ number: i + 1 })),
  },
  { name: 'Runtime Soak', status: 'completed', conclusion: 'skipped', steps: [] },
];

describe('runNeverStarted', () => {
  it('recognises a run whose jobs never executed a single step', () => {
    expect(runNeverStarted(budgetBlocked)).toBe(true);
  });

  it('does not excuse a run that failed after actually running steps', () => {
    expect(runNeverStarted(meritFailure)).toBe(false);
  });

  it('treats a run with no jobs at all as never started', () => {
    // A workflow that fails to start produces no jobs. Nothing executed, so
    // there is no compatibility evidence either way.
    expect(runNeverStarted([])).toBe(true);
  });

  it('blocks rather than excuses when the job list cannot be read', () => {
    // An API error must never be mistaken for "the budget ran out". If we
    // cannot tell, the release gate keeps its teeth.
    expect(runNeverStarted(null)).toBe(false);
    expect(runNeverStarted(undefined)).toBe(false);
  });

  it('counts a job whose steps key is missing as having run nothing', () => {
    expect(runNeverStarted([{ name: 'x', conclusion: 'failure' }])).toBe(true);
  });
});
