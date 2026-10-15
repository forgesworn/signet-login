import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const RELEASE_ONLY_PATHS = new Set([
  '.github/workflows/release.yml', 'docs/release-app.md', 'CHANGELOG.md',
  'tools/check-consumer-compatibility.mjs', 'tools/consumer-public-evidence.mjs',
  'tools/consumer-public-contracts.json', 'tools/consumer-release-payload.mjs',
  'tests/consumer-public-evidence.test.ts', 'tests/consumer-release-payload.test.ts',
]);
const digest = value => createHash('sha256').update(value).digest('hex');

// Read regular members and hashes only. Never extract an untrusted archive.
const INSPECT_ARCHIVE = `import hashlib,json,pathlib,sys,tarfile
result={}
with tarfile.open(sys.argv[1], 'r:gz') as archive:
 for member in archive:
  name=member.name
  if not member.isfile() or not name.startswith('package/') or any(p in ('','..','.') for p in name.split('/')):
   raise ValueError('Non-regular or unsafe package member')
  name=name[len('package/'):]
  if name in result or member.size > 32000000: raise ValueError('Duplicate or oversized package member')
  stream=archive.extractfile(member)
  result[name]=hashlib.sha256(stream.read()).hexdigest()
print(json.dumps(result))
`;

export function verifyReleasePayload({ repoDir = process.cwd(), candidateSha, releaseSha, archive }) {
  const fail = () => { throw new Error('Release payload does not match the tested SDK candidate'); };
  if (![candidateSha, releaseSha].every(value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value)) || typeof archive !== 'string') fail();
  const git = (...args) => execFileSync('git', args, { cwd: repoDir, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32_000_000 });
  try {
    if (git('rev-parse', 'HEAD').toString().trim() !== releaseSha) fail();
    git('merge-base', '--is-ancestor', candidateSha, releaseSha);
    const changes = git('diff', '--name-only', '-z', candidateSha, releaseSha).toString().split('\0').filter(Boolean);
    if (changes.some(path => !RELEASE_ONLY_PATHS.has(path))) fail();
    const entries = git('ls-tree', '-rz', candidateSha, '--', 'package.json', 'README.md', 'LICENSE', 'dist', 'examples', 'llms.txt')
      .toString().split('\0').filter(Boolean);
    const expected = {};
    for (const entry of entries) {
      const match = /^(100644|100755) blob [a-f0-9]{40}\t(.+)$/.exec(entry);
      if (!match) fail();
      expected[match[2]] = digest(git('show', `${candidateSha}:${match[2]}`));
    }
    if (!Object.hasOwn(expected, 'package.json') || !Object.keys(expected).some(path => path.startsWith('dist/'))) fail();
    const observed = JSON.parse(execFileSync('python3', ['-c', INSPECT_ARCHIVE, resolve(repoDir, archive)], {
      cwd: repoDir, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 2_000_000,
    }).toString());
    const files = Object.keys(expected).sort();
    if (JSON.stringify(files) !== JSON.stringify(Object.keys(observed).sort()) || files.some(path => expected[path] !== observed[path])) fail();
    return { candidateSha, releaseSha, files: files.map(path => ({ path, sha256: expected[path] })) };
  } catch {
    fail();
  }
}

// Anvil rebuilds independently after the compatibility job. Check its actual
// freshly packed output too, before it records the canonical publication tarball.
export function verifyCurrentBuild({ repoDir = process.cwd(), candidateSha, releaseSha } = {}) {
  if (![candidateSha, releaseSha].every(value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value))) {
    throw new Error('Expected validated candidate and release commit SHAs');
  }
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repoDir, encoding: 'utf8' }).trim();
  if (head !== releaseSha) throw new Error('Publisher checkout differs from the compatibility checkout');
  // Anvil's checkout is shallow. Recover ancestry for the same fixed commit;
  // changing a remote tag cannot change the already checked-out HEAD.
  if (execFileSync('git', ['rev-parse', '--is-shallow-repository'], { cwd: repoDir, encoding: 'utf8' }).trim() === 'true') {
    execFileSync('git', ['fetch', '--unshallow', '--no-tags', 'origin'], { cwd: repoDir, stdio: ['ignore', 'pipe', 'pipe'] });
  }
  const destination = resolve(repoDir, 'release/candidates/current-build');
  mkdirSync(destination, { recursive: true });
  const packs = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', destination], {
    cwd: repoDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 2_000_000,
  }));
  if (packs.length !== 1 || !/^[a-z0-9.-]+\.tgz$/.test(packs[0].filename)) throw new Error('Unexpected current-build package');
  return verifyReleasePayload({ repoDir, candidateSha, releaseSha, archive: resolve(destination, packs[0].filename) });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 5 || process.argv[2] !== '--check-current-build') throw new Error('Expected --check-current-build and two commit SHAs');
    const proof = verifyCurrentBuild({ candidateSha: process.argv[3], releaseSha: process.argv[4] });
    console.log(`Verified ${proof.files.length} publisher package files against tested SDK ${proof.candidateSha}.`);
  } catch {
    console.error('Publisher package does not match the tagged SDK source.');
    process.exitCode = 1;
  }
}
