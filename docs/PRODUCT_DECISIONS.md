# Product decisions

Written on 2026-10-19, when lockspect was started. It records why this product was chosen and how it is scoped.

## How the idea was chosen

The reference projects were [`adembc/lazyssh`](https://github.com/adembc/lazyssh) (about 4k stars: a TUI that makes a familiar but fiddly tool pleasant) and [`rankme.fast`](https://github.com/SelmiAbderrahim/rankme.fast) (about 750 stars: a self-hosted alternative to paid SaaS). Both took a well-known, recurring job and made it effortless.

Sources looked at: GitHub repositories created since July 2026, sorted by stars; the most-reacted GitHub issues of 2026; Show HN posts with 150+ points from the last 60 days; HN comment searches for tool requests; and competitor sites.

### Candidates considered

| #   | Idea                                                       | Evidence                        | Competition                                                 | Verdict                      |
| --- | ---------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------- | ---------------------------- |
| 1   | MCP config converter (Claude/Cursor/VS Code/Codex formats) | Many people building it         | mcp.directory and dev-toolbox converters, several sync CLIs | Crowded, low differentiation |
| 2   | Universal "install this MCP server" button                 | Many README install sections    | install.apicommons.org already does it                      | Already solved               |
| 3   | `lazyports`-style port/process TUI                         | lazy* pattern works             | LazyPorts (98★), several others                             | Taken                        |
| 4   | Cron/systemd TUI                                           | Weak                            | lazycron and others                                         | Low demand                   |
| 5   | Git worktree TUI                                           | Agent workflows need worktrees  | lazyworktree (308★)                                         | Taken                        |
| 6   | Claude Code / Codex usage analyser                         | Frequent quota complaints       | ccusage dominates                                           | Taken                        |
| 7   | Agent session viewer                                       | Agent activity is high          | zoetrope and many others                                    | Crowded                      |
| 8   | AGENTS.md / CLAUDE.md sync                                 | Claude Code issue with 418 👍   | rulesync, ruler                                             | Taken                        |
| 9   | Dependency cooldown config checker                         | depsguard (386★) shows interest | depsguard, dep-cooldown                                     | Narrow on its own            |
| 10  | **Lockfile supply-chain inspector**                        | See below                       | Partial, closed-source, or CLI-only                         | **Chosen**                   |

### Evidence for the chosen idea

- **Repeated npm compromises in 2026.** The most-reacted issues of the year include `axios@1.14.1 and axios@0.30.4 are compromised` (701 👍) with a post-mortem (594 👍), `TanStack/router: several npm latest releases were compromised` (215 👍), a malicious `litellm` release (798 👍), and a VS Code request for `minimumReleaseAge` on extensions (333 👍).
- **The existing audit path broke.** `pnpm audit` failed with HTTP 410 after npm retired its legacy audit endpoints ([pnpm#11265](https://github.com/pnpm/pnpm/issues/11265), 270 👍).
- **Release cooldowns went mainstream.** npm (`min-release-age`, 11.10), pnpm (`minimumReleaseAge`, 10.16, on by default in 11), Yarn (`npmMinimalAgeGate`, 4.10) and Bun (`minimumReleaseAge`, 1.3) all added them. Several guides compare the settings, and [arnica/depsguard](https://github.com/arnica/depsguard) (386★) hardens configs. Nothing showed which versions _already in your lockfile_ fall inside the window.
- **The data is free and browser-accessible.** OSV.dev `querybatch` returns `MAL-*` malware advisories as well as GHSA/CVE. deps.dev `versionbatch` returns publish date, licences, deprecation and provenance attestations. Both allow CORS (deps.dev only for "simple" requests, see below), so a static site can do everything.

### Closest alternatives

| Tool                       | Strength                            | Gap lockspect fills                                                                                  |
| -------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `npm audit` / `pnpm audit` | Built in                            | One package manager each; CVEs only; no age, unpublished or provenance signal; pnpm's was broken     |
| osv-scanner (Google)       | Excellent coverage, many ecosystems | Go binary to install; vulnerabilities only; no cooldown, licence or provenance view; no browser UI   |
| DependencyWatch.io         | In-browser compromise check         | Closed source; curated incident list only (no general advisories, age or licences); no CI exit codes |
| NPMScan                    | Heuristic malware analysis          | Reads `package.json` ranges, not the resolved versions you actually installed                        |
| Socket.dev, Snyk           | Deep analysis                       | Accounts, GitHub app install, paid tiers                                                             |
| depsguard, dep-cooldown    | Cooldown config                     | Configuration only, or no UI                                                                         |

**Unique position:** one open-source tool, usable in a browser tab with zero install _and_ as a zero-dependency CLI / GitHub Action. It covers every major JS lockfile format and combines malware, vulnerabilities, release age, unpublished versions, install scripts, licences and provenance.

## Product definition

- **Target user:** JavaScript and TypeScript developers and maintainers, and the security-minded lead who has just read about another npm compromise.
- **Problem:** "Is anything in our lockfile malicious, vulnerable, suspiciously new, or gone from npm?" Answering that today means several tools, each covering one package manager or one signal.
- **Pitch:** _Drop your lockfile and see malware, vulnerabilities and too-fresh releases in seconds. In your browser, nothing uploaded._
- **Core workflow:** drop / choose / paste a lockfile → about 3 seconds of lookups → verdict, counts and a ranked list → expand a package for advisories and the fixing version → copy Markdown for the PR, or the cooldown snippet for your package manager.
- **Smallest complete version:** five lockfile formats; OSV + deps.dev + npm-registry fallback; web UI with filters and export; CLI with `--fail-on` and exit codes; GitHub Action.
- **Discovery:** the live demo with a real detection one click away (the axios sample), README landing page, GitHub topics, the GitHub Action (Marketplace-ready `action.yml`), and posts where people discuss supply-chain incidents.
- **Verification:** real lockfiles generated by npm 6/11, pnpm 7/8/10, Yarn 1/4 and Bun 1.3 as fixtures; mocked-network unit and integration tests; live API tests; Playwright end-to-end tests on desktop and mobile; and a check of the deployed site.

## Notable technical decisions

- **No backend.** Privacy is the product: the lockfile never leaves the device, and only `name@version` pairs go to public APIs. GitHub Pages hosting is free.
- **deps.dev requests use `Content-Type: text/plain`.** deps.dev answers CORS preflights with HTTP 400, so a JSON content type fails in browsers. `text/plain` keeps the POST a CORS "simple request" and deps.dev still parses the body. This was found by the first browser test, not by unit tests.
- **npm registry fallback, capped at 150 lookups.** deps.dev may not have indexed a version published minutes ago, and it has no record of unpublished versions. Those are exactly the dangerous cases, so they are checked against `registry.npmjs.org`, whose full documents are large, hence the cap.
- **Incomplete beats wrong.** If OSV or deps.dev fails, the UI says "Scan incomplete" instead of "No known malware", and the CLI exits 2 unless `--allow-incomplete` is passed.
- **Committed CLI bundle.** `dist/cli/lockspect.mjs` is committed so that `npx github:feresbr1/lockspect` and `uses: feresbr1/lockspect@v1` work without an npm account or a build step. CI fails if it is stale.
- **Preact + Vite, self-hosted IBM Plex fonts.** The app has a small bundle and makes no third-party font requests.
