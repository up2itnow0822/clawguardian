#!/usr/bin/env node
/**
 * `prepare` hook: build a clean dist/ for `npm pack`, `npm publish` and
 * GitHub (git-dependency) installs.
 *
 * TypeScript is a devDependency, so a source-checkout install with dev deps
 * omitted (`npm ci --omit=dev`, NODE_ENV=production) has no compiler. That
 * case skips the build instead of failing; packing or publishing without a
 * compiler is still a hard error so a dist-less tarball can never ship.
 */
const { rmSync } = require('fs');
const { join } = require('path');
const { execFileSync } = require('child_process');

const root = join(__dirname, '..');
const packaging = ['pack', 'publish'].includes(process.env.npm_command || '');

let tsc;
try {
  tsc = require.resolve('typescript/bin/tsc', { paths: [root] });
} catch {
  if (packaging) {
    console.error('prepare: typescript is not installed; cannot build dist for npm ' + process.env.npm_command);
    process.exit(1);
  }
  console.warn('prepare: typescript not installed (dev dependencies omitted); skipping build');
  process.exit(0);
}

// Wipe dist first so stale or renamed modules are never packaged.
rmSync(join(root, 'dist'), { recursive: true, force: true });
execFileSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.json')], { cwd: root, stdio: 'inherit' });
