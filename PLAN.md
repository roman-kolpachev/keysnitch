# Plan

## Status

- 2026-11-06, v0.1.0 (PR #3, merged): pattern parser, safety check and compiler; `scan`, `mask`, `findRules`, `vendors`, `defineRule`, custom matchers; 250 built-in rules (220 from gitleaks v8.30.1, 30 own); parity with the website checker; contract tests for every rule; repository checks. Private repository, not published.
- 2026-11-06: Secret Sentinel runs on keysnitch (its PR #63, on development). Leak corpus of 1 Nov 2026: 1391 of 1400 (README, "How it compares").
- 2026-11-06: dependabot PRs #1 (TypeScript 7) and #2 (@types/node 26) closed: typescript-eslint supports TypeScript below 6.1, and the Node types must match the oldest Node in `engines` (24). `.github/dependabot.yml` ignores both until that changes.

## Mutation testing

Stryker 10.1.1 through npx (not a dependency), command runner with node:test, 2026-11-06, on `src/pattern/*`, `scan.ts`, `rule.ts`, `mask.ts`, `search.ts`, `entropy.ts`, `placeholder.ts` and the helpers of `src/rules/keysnitch.ts`: 1789 mutants, score **90.2 %** (1599 killed, 14 timed out, 176 survived). A survivor checked by hand (the digit test in `isKebabCase`) is killed by the tests, so the command runner misses some kills; the score is a lower bound. Survivors that showed real gaps got tests the same night (lookahead with mixed options, the entropy boundary, a custom matcher at offset 0 and with bad facts, naming by the wider specific rule, `maxFindings: 1`, error texts); each was checked by hand to fail without the code. Survivors left are equivalent (a `<=` on a loop end that only reads `undefined`, the sort order of equal starts that the union makes irrelevant, `minEntropy >= 0` where entropy is never negative) or messages of `RuleError`.

Config used: `testRunner: command`, `coverageAnalysis: off`, `concurrency: 2`, `tsconfigFile` pointed at a missing file (Stryker's tsconfig rewrite needs its own TypeScript). Run it again before 1.0.

## Next

1. More vendors with published prefixes that neither gitleaks nor the website checker has. Ideas: Heroku platform keys in new formats, Okta, Datadog application keys, Jenkins API tokens (no prefix, needs a context word), Cloudflare API tokens in new formats.
2. Before going public: turn on GitHub private vulnerability reporting, secret scanning and push protection; check that CI runs; publish to npm with provenance.

## Questions for the owner

1. **License.** MIT is the default (same as gitleaks and secretlint). Change before the repository goes public if you want Apache-2.0.
2. **"1Password" after a colon** is reported by the setting rule (D-8). Default: keep it, the rule finds real passwords in YAML that way. Alternative: a list of brand names to skip.
3. **Values with `&` in a URL query.** The setting rule takes `token=...&next=1` up to the next space, because a password may hold `&`. Default: keep (more is hidden, nothing stays readable). Alternative: stop at `&` inside URLs only.
4. **Website checker bug.** Its Sentry pattern `sntr[yu]s_` accepts "sntrus_" (not a real prefix) and misses user tokens (`sntryu_`). keysnitch finds both real prefixes. The owner wants it fixed (2026-11-06); the checker may move to keysnitch once it is on npm.

## Ideas found while building

- A `redact()` helper that writes a marker per finding (Secret Sentinel has its own markers, so it stays out of v0.1.0).
- Checksum validation for GitHub and npm tokens (CRC32): fewer false positives, but only where the vendor documents it.
