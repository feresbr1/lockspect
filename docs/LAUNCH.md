# Launch kit

Material for announcing lockspect. Nothing here has been posted yet. Every channel below needs the maintainer's own account, and each community's self-promotion rules must be followed. Post where it is genuinely relevant, answer questions yourself, and do not cross-post the same text everywhere on the same day.

**Assets:** live demo https://feresbr1.github.io/lockspect/ · repo https://github.com/feresbr1/lockspect · screenshots in [`docs/images`](images/) · social card [`public/og.png`](../public/og.png)

---

## One-liners

- **Short:** Drop your lockfile and see malware, vulnerabilities and too-fresh releases in seconds. In your browser, nothing uploaded.
- **Technical:** lockspect parses npm, pnpm, Yarn and Bun lockfiles and checks every resolved version against OSV.dev (malware + advisories), deps.dev (publish date, licence, provenance) and the npm registry (unpublished versions). It runs as a static site, a zero-dependency CLI or a GitHub Action.

## GitHub announcement / release blurb

> **lockspect 1.0: is your lockfile hiding something?**
>
> After the axios and TanStack compromises this year, the question "did we install a bad version?" kept coming up, and the answer needed a different tool for every package manager. lockspect reads `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and Berry) and `bun.lock`, then flags:
>
> - known malware (OSV `MAL-*` advisories) and GHSA/CVE vulnerabilities, with the fixing version
> - versions published inside your release-cooldown window
> - versions that are no longer on npm
> - install scripts, deprecations, copyleft licences, and provenance coverage
>
> Your lockfile never leaves the browser; only `name@version` pairs are looked up. The same checks run in CI: `npx github:feresbr1/lockspect --fail-on malware,vuln:critical` or `uses: feresbr1/lockspect@v1`.

## Show HN

Hacker News: a Show HN must be something people can try right away, with no sign-up wall. lockspect qualifies. Post on a weekday morning (US time), then stay to answer comments.

**Title (≤ 80 chars):** `Show HN: Lockspect – check a lockfile for malware and too-fresh npm releases`

**Text:**

> I built lockspect after the axios compromise this spring (axios@1.14.1 pulled in a payload package, plain-crypto-js@4.2.1). The question every team asked was "is it in our lockfile?", and the answer depended on the package manager: npm audit is npm-only, pnpm audit was returning 410s after npm retired its old audit endpoints, and neither tells you which versions are only hours old.
>
> lockspect parses package-lock (v1–3), pnpm-lock (5/6/9), yarn.lock (classic + Berry) and bun.lock in the browser. It sends only name@version pairs to OSV.dev (which includes the OpenSSF malicious-packages feed as MAL-* advisories) and deps.dev (publish time, licences, provenance attestations). For versions deps.dev hasn't indexed, which are usually brand-new or unpublished versions, the dangerous ones, it falls back to the npm registry.
>
> Things I found interesting while building it:
>
> - deps.dev answers CORS preflights with a 400, so the batch endpoint is called with a text/plain body to stay a "simple request".
> - Release cooldowns (`min-release-age` in npm 11.10, `minimumReleaseAge` in pnpm/Bun, `npmMinimalAgeGate` in Yarn) use days, minutes and seconds respectively, so the tool generates the snippet in the right unit.
> - If a data source fails, the page says "scan incomplete" rather than "no malware".
>
> There's a sample lockfile that reproduces the axios case, a zero-dependency CLI with --fail-on exit codes, and a GitHub Action. MIT licensed. Feedback on lockfile formats it gets wrong is very welcome.

## Reddit

Read each subreddit's sidebar rules before posting. Most limit self-promotion (a common rule of thumb is that it should be a small share of your activity there), and some only allow it on a set day.

| Subreddit     | Fit    | Notes                                                                  |
| ------------- | ------ | ---------------------------------------------------------------------- |
| r/javascript  | High   | Allows project posts; lead with the problem, not the tool              |
| r/node        | High   | Frame around CI usage (`--fail-on`, the GitHub Action)                 |
| r/webdev      | Medium | Self-promotion only in the _Showoff Saturday_ thread                   |
| r/devops      | Medium | Frame around supply-chain gates in pipelines                           |
| r/pnpm, r/bun | Medium | Small; useful for format-specific feedback                             |
| r/netsec      | Low    | Strict technical bar; only with a write-up, e.g. the cooldown analysis |

**Suggested title (r/javascript):** _I built a browser tool that tells you if your lockfile contains malicious, unpublished or hours-old package versions (npm/pnpm/Yarn/Bun)_

**Body:** a shorter version of the Show HN text, plus the screenshot `docs/images/report.png`.

## Other communities

- **dev.to / Hashnode article:** _"Which of my dependencies are younger than 7 days? Release cooldowns for npm, pnpm, Yarn and Bun, explained"_. Search-friendly; embed the cooldown table and link lockspect as the checker.
- **Mastodon (infosec.exchange, fosstodon.org) and Bluesky:** short post with the screenshot and the #npm #supplychain #javascript tags.
- **OpenSSF Slack, #malicious-packages:** mention that lockspect surfaces their feed to end users. Ask first rather than advertise.
- **Discussions after the next npm incident:** when a new compromise hits, reply with how to check for it (the sample button already shows the axios case). That is the most natural moment for discovery.

## Directories and registries

| Where                                           | Action                                                                                              | Status                                                                             |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| GitHub Marketplace                              | Publish `action.yml` from the v1.0.0 release page ("Publish this Action to the GitHub Marketplace") | Pending: requires the maintainer to accept the Marketplace agreement in the web UI |
| npm registry                                    | `npm publish` (the `bin` and `files` fields are ready)                                              | Pending: needs an npm account (`npm login`)                                        |
| awesome-nodejs (sindresorhus)                   | PR under _Command-line apps_ or _Security_                                                          | Pending: their list requires some adoption first                                   |
| awesome-devsecops, awesome-security-tools lists | PR                                                                                                  | Pending                                                                            |
| OSV.dev "integrations" page                     | Ask to be listed as a consumer of the API                                                           | Pending                                                                            |

## Integration opportunities

- **Renovate / Dependabot:** link lockspect from cooldown documentation discussions. The tool already generates both configs.
- **pnpm / Yarn / Bun issue trackers:** where users ask "how do I check what's inside my cooldown window", a link is on-topic.
- **VS Code extension:** decorate `package-lock.json` with the same flags (future).
- **PR bot:** the GitHub Action already writes Markdown to the job summary; posting it as a PR comment is a small addition.

## Keywords and search queries

`check package-lock.json for malware` · `is my lockfile compromised` · `scan pnpm-lock.yaml vulnerabilities` · `yarn.lock security scanner online` · `bun.lock audit` · `npm audit alternative` · `pnpm audit 410` · `npm supply chain attack check` · `axios 1.14.1 compromised check` · `plain-crypto-js` · `minimum release age npm` · `min-release-age` · `minimumReleaseAge pnpm` · `npmMinimalAgeGate` · `dependency cooldown` · `unpublished npm version in lockfile` · `npm provenance check` · `osv scanner online`

## After launch

- Watch issues for lockfiles that parse incorrectly. Each one becomes a real fixture.
- Do not buy stars, trade upvotes or ask friends to brigade a post.
