/**
 * Telling "this consumer is incompatible" apart from "this consumer never ran".
 *
 * A workflow run that GitHub refuses to start - an exhausted Actions budget is
 * the case that prompted this - completes with conclusion "failure", exactly
 * like a run whose tests failed on their merits. The release gate read both as
 * incompatibility and blocked the publish, so a billing lapse in one private
 * consumer silently held a library release for five weeks.
 *
 * The difference is only visible one level down: a job that was never started
 * carries no steps. A job that ran and failed carries the steps it got through.
 */

function stepCount(job) {
  return Array.isArray(job?.steps) ? job.steps.length : 0;
}

/**
 * True when nothing in the run executed, so it carries no evidence either way.
 *
 * Deliberately conservative: anything we cannot read is reported as a real
 * failure, because mistaking a broken API call for "the budget ran out" would
 * publish on the strength of a check that never happened.
 *
 * @param {unknown} jobs - the `jobs` array from /actions/runs/{id}/jobs
 * @returns {boolean}
 */
export function runNeverStarted(jobs) {
  if (!Array.isArray(jobs)) return false;
  return jobs.every(job => stepCount(job) === 0);
}
