# LinkedIn post

Ready to copy and paste. Attach the image listed below (a real screenshot from the project). LinkedIn
tends to show posts with external links to fewer people, so a common approach is to put the links in
the first comment instead of the post. The post works either way.

**Image to attach:** `docs/images/report.png`

**First comment (optional):** Try it: https://feresbr1.github.io/lockspect/ · Code: https://github.com/feresbr1/lockspect

---

Your lockfile remembers every version you ever installed. Including the malicious ones.

In March 2026 a hijacked release, axios@1.14.1, shipped a payload through a new dependency. Both versions were pulled from npm, but every project that installed them in that window still has them written in its lockfile.

So I built lockspect: drop a package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock and see in seconds which exact versions are:

🟥 known malware (OSV.dev MAL advisories)
🟧 vulnerable, with the version that fixes them
🟪 no longer on npm (often removed malware)
🟨 too fresh to trust, inside your release cooldown window
🟦 running install scripts
⬜ deprecated or strong copyleft

It also generates the config to refuse fresh releases at install time for npm, pnpm, Yarn, Bun, Renovate and Dependabot.

It runs in your browser (the lockfile never leaves the tab), in your terminal, and in CI. No account, no install. Open source, MIT.

🔗 https://feresbr1.github.io/lockspect/
💻 https://github.com/feresbr1/lockspect

#opensource #npm #javascript #supplychainsecurity #devsecops
