# Security Policy

## Supported versions

Only the latest release and the live site at https://feresbr1.github.io/lockspect/ receive fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Report it privately through [GitHub security advisories](https://github.com/feresbr1/lockspect/security/advisories/new).

Things that count as vulnerabilities here include:

- a crafted lockfile that executes script in the lockspect page or the CLI,
- lockspect sending anything other than package names and versions to a third party,
- a lockfile that makes lockspect report a known-malicious version as clean.

## Reporting a malicious npm package

lockspect does not keep its own malware list. It reads [OSV.dev](https://osv.dev). To get a malicious package flagged, report it to npm (`npm report <package>` or https://www.npmjs.com/support) and to the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) project, which feeds OSV.
