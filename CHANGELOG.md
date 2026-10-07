# Changelog

## [0.1.1] - 2026-10-07

Docs only. The shipped code (`dist/`) is byte-identical to 0.1.0.

### Changed
- README: install with `npm install -g clawpowers-guardian` / `npx clawpowers-guardian` now that the package is on npm (removed the "install from GitHub, npm package coming soon" note) and restored the npm badge.

## [Unreleased]

### Changed
- Publishable package name is now `clawpowers-guardian` so install badges and commands no longer point at the unrelated npm package `clawguardian`.
- Related-project npm link now uses `agentwallet-sdk` (the previous `agent-wallet-sdk` URL was a 404 typo).

### Fixed
- npm tarball now ships every compiled module: `package.json` declares `files` (`dist` plus docs), so the `.gitignore` `*.js` rule no longer drops `dist/scanner`, `dist/policy` and `dist/reporting` and the CLI no longer crashes with `Cannot find module '../scanner/guardian'`.
- `scan` and `ci` no longer hang for 30 seconds after finishing; the per-stage timeout timer is now cleared.
- Added a clean `prepare` build (`scripts/prepare.cjs`: wipes `dist`, then compiles; runs on `npm pack`, `npm publish` and GitHub installs, and skips cleanly when dev dependencies are omitted), a `bugs` URL, a Jest CLI smoke test, and a working `lint` script.

## [0.1.0] - 2026-03-22

### Added
- Initial release
- ClawGuardian agent identity verification middleware
- Request validation and reputation scoring
- Rate limiting and permission management
