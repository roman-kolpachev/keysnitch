# Plan

## Status

- 2026-11-06, v0.1.0 (PR #3, merged): pattern parser, safety check and compiler; `scan`, `mask`, `findRules`, `vendors`, `defineRule`, custom matchers; 250 built-in rules (220 from gitleaks v8.30.1, 30 own); parity with the website checker; contract tests for every rule; repository checks. Private repository, not published.
- 2026-11-06: Secret Sentinel for Jira and Confluence runs on keysnitch (in testing). Leak corpus of 1 Nov 2026: 1391 of 1400 (README, "How it compares").
- 2026-11-06: the rules that keep the code safe moved from ESLint into `test/repo.test.ts` (PR #6).
- 2026-11-06: Sourcegraph rule no longer takes git commit hashes for tokens (PR #9, found by scanning the repository's own history).
- 2026-11-06: ready to publish: CI on Node 24 and 26, a release workflow with npm provenance, badges, changelog links, workflow tests (actions pinned to commit hashes, read-only tokens).
- 2026-11-06: oxlint instead of ESLint, TypeScript 7.0.2 (docs/decisions.md, D-11). Dependabot PR #1 (TypeScript 7) is done by this; PR #2 (@types/node 26) is not taken: the Node types match the oldest Node in `engines` (24, also Forge's).

## Mutation testing

Stryker 10.1.1 through npx (not a dependency), command runner with node:test, 2026-11-06, on `src/pattern/*`, `scan.ts`, `rule.ts`, `mask.ts`, `search.ts`, `entropy.ts`, `placeholder.ts` and the helpers of `src/rules/keysnitch.ts`: 1789 mutants, score **90.2 %** (1599 killed, 14 timed out, 176 survived). A survivor checked by hand (the digit test in `isKebabCase`) is killed by the tests, so the command runner misses some kills; the score is a lower bound. Survivors that showed real gaps got tests the same night (lookahead with mixed options, the entropy boundary, a custom matcher at offset 0 and with bad facts, naming by the wider specific rule, `maxFindings: 1`, error texts); each was checked by hand to fail without the code. Survivors left are equivalent (a `<=` on a loop end that only reads `undefined`, the sort order of equal starts that the union makes irrelevant, `minEntropy >= 0` where entropy is never negative) or messages of `RuleError`.

Config used: `testRunner: command`, `coverageAnalysis: off`, `concurrency: 2`, `tsconfigFile` pointed at a missing file (Stryker's tsconfig rewrite needs its own TypeScript). Run it again before 1.0.

## Next

1. More vendors with published prefixes that neither gitleaks nor the website checker has. Ideas: Heroku platform keys in new formats, Okta, Datadog application keys, Jenkins API tokens (no prefix, needs a context word), Cloudflare API tokens in new formats.
2. When the repository goes public: turn on private vulnerability reporting, secret scanning and push protection, delete branches after merge, add topics; check that CI runs. Publish 0.1.0 by hand once (the package must exist before npm trusted publishing can be set up), then add this repository's `release.yml` as the trusted publisher on npmjs.com; later versions go out through GitHub releases.

## Open questions

1. **"1Password" after a colon** is reported by the setting rule (D-8). Default: keep it, the rule finds real passwords in YAML that way. Alternative: a list of brand names to skip.
2. **Values with `&` in a URL query.** The setting rule takes `token=...&next=1` up to the next space, because a password may hold `&`. Default: keep (more is hidden, nothing stays readable). Alternative: stop at `&` inside URLs only.

## Ideas found while building

- A `redact()` helper that writes a marker per finding (Secret Sentinel, the first user, has its own markers, so it stays out of v0.1.0).
- Checksum validation for GitHub and npm tokens (CRC32): fewer false positives, but only where the vendor documents it.
