# Plan

## Status

- 2026-11-06, v0.1.0 (branch `feat/v0.1.0`): pattern parser, safety check and compiler; `scan`, `mask`, `findRules`, `vendors`, `defineRule`, custom matchers; 248 built-in rules (220 from gitleaks v8.30.1, 28 own); parity with the website checker; contract tests for every rule; repository checks. Private repository, not published.

## Next

1. Secret Sentinel uses keysnitch instead of secretlint (in the Secret Sentinel repository).
2. Re-run the 1 Nov 2026 corpus (marketplace-insights `research/2026-11-01-secret-sprawl/`) through keysnitch and publish the numbers in `docs/benchmark.md`.
3. More vendors with published prefixes that neither gitleaks nor the website checker has. Ideas: Heroku platform keys in new formats, Okta, Datadog application keys, Jenkins API tokens (no prefix, needs a context word), Cloudflare API tokens in new formats.
4. Before going public: turn on GitHub private vulnerability reporting, secret scanning and push protection; check that CI runs; publish to npm with provenance.

## Questions for the owner

1. **License.** MIT is the default (same as gitleaks and secretlint). Change before the repository goes public if you want Apache-2.0.
2. **"1Password" after a colon** is reported by the setting rule (D-8). Default: keep it, the rule finds real passwords in YAML that way. Alternative: a list of brand names to skip.
3. **Values with `&` in a URL query.** The setting rule takes `token=...&next=1` up to the next space, because a password may hold `&`. Default: keep (more is hidden, nothing stays readable). Alternative: stop at `&` inside URLs only.
4. **Website checker bug.** Its Sentry pattern `sntr[yu]s_` accepts "sntrus_" (not a real prefix) and misses user tokens (`sntryu_`). keysnitch finds both real prefixes. Default: fix the checker in web2 when someone works there next.

## Ideas found while building

- A `redact()` helper that writes a marker per finding (Secret Sentinel has its own markers, so it stays out of v0.1.0).
- Checksum validation for GitHub and npm tokens (CRC32): fewer false positives, but only where the vendor documents it.
