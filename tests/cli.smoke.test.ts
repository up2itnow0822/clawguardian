/**
 * CLI smoke test: builds dist/, runs the published bin entry point, and checks
 * that `npm pack` ships every compiled module the CLI needs (and nothing else).
 */
import { execFileSync, spawnSync } from 'child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative, sep } from 'path';

const ROOT = join(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'index.js');
const FIXTURE = join(__dirname, 'fixtures', 'hello-skill');
const DOCS = ['README.md', 'LICENSE', 'CHANGELOG.md', 'package.json'];

/** Run npm portably: via npm's own JS entry when available, else through a shell (npm.cmd on Windows). */
function runNpm(args: string[]): string {
  const npmCli = process.env.npm_execpath;
  // Only trust npm's own CLI entry; `npx jest` sets this to npx-cli.js instead.
  if (npmCli && /npm-cli\.c?js$/.test(npmCli)) {
    return execFileSync(process.execPath, [npmCli, ...args], { cwd: ROOT, encoding: 'utf-8' });
  }
  return execFileSync('npm', args, { cwd: ROOT, encoding: 'utf-8', shell: true });
}

function runCli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, encoding: 'utf-8' });
}

function listTs(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listTs(full) : full.endsWith('.ts') ? [full] : [];
  });
}

beforeAll(() => {
  rmSync(join(ROOT, 'dist'), { recursive: true, force: true });
  execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', 'tsconfig.json'], {
    cwd: ROOT,
    stdio: 'inherit',
  });
});

describe('clawpowers-guardian CLI', () => {
  it('prints usage for --help and exits 0', () => {
    const res = runCli(['--help']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Usage:');
    expect(res.stdout).toContain('clawguardian scan <path>');
  });

  it('scans a fixture skill directory', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cg-smoke-'));
    const out = join(tmp, 'report.json');
    try {
      const started = Date.now();
      const res = runCli(['scan', FIXTURE, '--format', 'json', '--output', out]);
      // A dangling stage-timeout timer used to keep the process alive for 30s.
      expect(Date.now() - started).toBeLessThan(15000);
      expect(res.stderr).toBe('');
      expect(res.status).toBe(0);
      expect(res.stdout).toContain(`Scanning: ${FIXTURE}`);
      expect(res.stdout).toContain('Recommendation:');

      const report = JSON.parse(readFileSync(out, 'utf-8'));
      expect(['safe', 'review', 'block']).toContain(report.recommendation);
      expect(typeof report.trustScore.overall).toBe('number');
      expect(Array.isArray(report.threats)).toBe(true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('npm pack ships all compiled modules and only dist + docs', () => {
    const raw = runNpm(['pack', '--dry-run', '--json', '--ignore-scripts']);
    const files: string[] = JSON.parse(raw)[0].files.map((f: { path: string }) => f.path);

    for (const f of files) {
      expect(f.startsWith('dist/') || DOCS.includes(f)).toBe(true);
    }
    expect(files).toContain('dist/cli/index.js');
    expect(files).toContain('dist/index.js');

    const srcDir = join(ROOT, 'src');
    const expectedJs = listTs(srcDir)
      .map((ts) => 'dist/' + relative(srcDir, ts).split(sep).join('/').replace(/\.ts$/, '.js'))
      .sort();
    // Every source module ships compiled, and no stale/orphaned module ships.
    expect(files.filter((f) => f.endsWith('.js')).sort()).toEqual(expectedJs);
    expect(existsSync(CLI)).toBe(true);
  });
});
