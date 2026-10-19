# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-19

### Added

- Web app (https://feresbr1.github.io/lockspect/) that scans a lockfile entirely in the browser.
- Parsers for `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (5.x, 6.x, 9.x), Yarn classic and Berry `yarn.lock`, and `bun.lock`, with npm alias and Yarn `patch:` resolution.
- Checks: malware and vulnerabilities (OSV.dev), publish age against a configurable cooldown, versions missing or unpublished from npm, install scripts, deprecation, licence classification and provenance (deps.dev, npm registry).
- Ready-to-paste release-cooldown config for npm, pnpm, Yarn, Bun, Renovate and Dependabot.
- Markdown and JSON export.
- Zero-dependency CLI (`npx github:feresbr1/lockspect`) with `--fail-on` rules and CI-friendly exit codes.
- Composite GitHub Action that writes the report to the job summary.

[1.0.0]: https://github.com/feresbr1/lockspect/releases/tag/v1.0.0
