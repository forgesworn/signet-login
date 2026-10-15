// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyCurrentBuild, verifyReleasePayload } from '../tools/consumer-release-payload.mjs';

const scratch: string[] = [];
afterEach(() => { for (const path of scratch.splice(0)) rmSync(path, { recursive: true, force: true }); });
function fixture() {
  const base = join(process.cwd(), 'release/candidates/payload-tests'); mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'case-')); scratch.push(dir);
  const git = (...args: string[]) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-q'); git('config', 'user.name', 'Payload test'); git('config', 'user.email', 'payload@example.invalid');
  mkdirSync(join(dir, 'dist')); mkdirSync(join(dir, 'tools'));
  writeFileSync(join(dir, 'package.json'), '{"name":"fixture","version":"0.18.2","files":["dist"]}');
  writeFileSync(join(dir, 'dist/index.js'), 'export const value = 1;\n');
  writeFileSync(join(dir, 'README.md'), 'Fixture\n');
  git('add', 'package.json', 'dist/index.js', 'README.md'); git('commit', '-qm', 'Candidate');
  const candidateSha = git('rev-parse', 'HEAD');
  const archive = join(dir, 'candidate.tgz');
  function pack(defect = '') {
    execFileSync('python3', ['-c', `import io,sys,tarfile,pathlib
root=pathlib.Path(sys.argv[1]); defect=sys.argv[2]
with tarfile.open(root/'candidate.tgz','w:gz') as archive:
 for name in ['package.json','dist/index.js','README.md']:
  if defect=='missing' and name=='README.md': continue
  data=(root/name).read_bytes()
  if defect=='changed' and name=='dist/index.js': data=b'changed'
  info=tarfile.TarInfo('package/'+name); info.size=len(data); archive.addfile(info,io.BytesIO(data))
 if defect in ['extra','duplicate','traversal','symlink']:
  name={'extra':'package/extra.js','duplicate':'package/README.md','traversal':'package/../README.md','symlink':'package/link'}[defect]
  info=tarfile.TarInfo(name)
  if defect=='symlink': info.type=tarfile.SYMTYPE; info.linkname='README.md'
  archive.addfile(info)
`, dir, defect]);
  }
  pack();
  return { dir, git, candidateSha, archive, pack, verify: () => verifyReleasePayload({ repoDir: dir, candidateSha, releaseSha: git('rev-parse', 'HEAD'), archive }) };
}
describe('candidate package identity at release', () => {
  it('checks the publisher build itself and refuses regenerated distribution drift', () => {
    const f = fixture(), expected = { repoDir: f.dir, candidateSha: f.candidateSha, releaseSha: f.candidateSha };
    expect(verifyCurrentBuild(expected).files).toHaveLength(3);
    writeFileSync(join(f.dir, 'dist/index.js'), 'unexpected regenerated code\n');
    expect(() => verifyCurrentBuild(expected)).toThrow();
  });
  it('refuses a tag checkout that moved after compatibility even if its build agrees with the new tag', () => {
    const f = fixture(); writeFileSync(join(f.dir, 'dist/index.js'), 'export const value = 2;\n');
    f.git('add', 'dist/index.js'); f.git('commit', '-qm', 'Moved tag');
    expect(() => verifyCurrentBuild({ repoDir: f.dir, candidateSha: f.candidateSha, releaseSha: f.candidateSha })).toThrow();
    expect(() => verifyCurrentBuild({ repoDir: f.dir, candidateSha: f.candidateSha, releaseSha: f.git('rev-parse', 'HEAD') })).toThrow();
  });
  it('allows reviewed release tooling changes while requiring identical packed file names and bytes', () => {
    const f = fixture(); writeFileSync(join(f.dir, 'tools/consumer-public-evidence.mjs'), '// release tool\n');
    f.git('add', 'tools/consumer-public-evidence.mjs'); f.git('commit', '-qm', 'Release tooling');
    expect(f.verify().files).toHaveLength(3);
  });
  for (const defect of ['missing', 'changed', 'extra', 'duplicate', 'traversal', 'symlink']) {
    it(`rejects a ${defect} tarball without extracting it`, () => { const f = fixture(); f.pack(defect); expect(f.verify).toThrow(); });
  }
  it('rejects runtime and package-control changes even with the old unchanged archive', () => {
    for (const file of ['package.json', 'dist/index.js', 'README.md']) {
      const f = fixture(); writeFileSync(join(f.dir, file), readFileSync(join(f.dir, file), 'utf8') + '\n');
      f.git('add', file); f.git('commit', '-qm', 'Unreviewed payload change'); expect(f.verify).toThrow();
    }
  });
  it('rejects an unrelated candidate or a release SHA other than the checkout', () => {
    const f = fixture();
    expect(() => verifyReleasePayload({ repoDir: f.dir, candidateSha: f.candidateSha, releaseSha: 'a'.repeat(40), archive: f.archive })).toThrow();
    expect(() => verifyReleasePayload({ repoDir: f.dir, candidateSha: 'b'.repeat(40), releaseSha: f.candidateSha, archive: f.archive })).toThrow();
  });
});
