# Decisions

Why keysnitch is built the way it is. Each entry says what was decided, why, and what it costs.

## D-1. An own engine instead of secretlint

keysnitch started as the detection engine of Secret Sentinel for Jira and Confluence, which used secretlint's recommended preset. A test on 1 Nov 2026 showed what that missed: 0 of 50 Atlassian API tokens, and less than the free checker on simplify-software.org overall. secretlint has about 50 rules and none for Atlassian, some of its rules report a range that cuts the secret short, its profiler slows down the longer a process runs, and several rules only run for certain file names.

So keysnitch is one table of rules with its own matcher. It covers every gitleaks rule for text, every format of the website checker, and the shapes secretlint finds (Secret Sentinel checks that last part against secretlint in its tests).

## D-2. The built-in RegExp engine with a safety check, not re2js

RE2 (and its JavaScript port re2js) is linear for any pattern, because it never backtracks. keysnitch writes its own patterns, so it can make them safe by shape instead (see docs/patterns.md) and keep the faster engine.

Measured with `node bench/regex.ts` (Node 24.22.1, about 1 MB of text, re2js 2.9.1):

| Shape                                                                    | Built-in RegExp |  re2js |
| ------------------------------------------------------------------------ | --------------: | -----: |
| prefix rule (`ghp_...`)                                                  |          0.2 ms | 0.6 ms |
| keyword rule (`(?:app_?key\|secret\|token)\s*[:=]...`, case-insensitive) |          0.8 ms | 155 ms |
| no prefix (three segments with dots)                                     |         20.5 ms | 0.1 ms |

re2js wins when a pattern has a rare literal in the middle, and loses badly on case-insensitive keyword rules, which are a large part of the rule set. A full scan with all 243 rules takes about 115 ms per MB of text. Other reasons:

- RE2 has no lookahead, which keysnitch uses to end a key without taking the next character (D-6).
- re2js would be the only runtime dependency of a security tool.

Where patterns cannot be checked (patterns typed by users), use RE2 through a custom matcher (README, "Patterns you cannot check"). Secret Sentinel does that with re2js for its customers' patterns.

## D-3. No runtime dependencies, few dev dependencies, node:test

A security tool should be easy to audit. keysnitch has no runtime dependencies (a test fails if one is added) and six dev dependencies: TypeScript, ESLint with typescript-eslint, Prettier and the Node types. Tests run on Node's own `node:test` with its coverage gate at 100 % of lines, branches and functions of `src/`. npm runs no install scripts (`.npmrc`).

TypeScript is 6.0.3, not 7: typescript-eslint supports TypeScript up to 6.0 today.

## D-4. gitleaks is the floor

Every rule id of the vendored gitleaks config must be a built-in rule, or be skipped with a written reason and a replacement (`test/rules/gitleaks-floor.test.ts`). Two are skipped: `pkcs12-file` matches file names, and `generic-api-key` guesses by entropy (replaced by keysnitch's setting rules, D-8).

The importer (`tools/gitleaks/`) drops the optional left context gitleaks patterns start with, bounds unbounded repeats, and runs each rule through the safety check. Hand-written changes are in `tools/gitleaks/overrides.ts`, each with its reason. Some fix gitleaks behaviour: the Google API key rule missed a key before `&` in a URL, `sentry-org-token` took the character after the token, and two rules reported a few characters (a capture group) instead of the whole key. `tools/gitleaks/also.ts` adds wider shapes from the website checker as a second branch of the gitleaks rule, so one credential keeps one rule.

## D-5. Case folding is ASCII only

`(?i)` folds A-Z and a-z and nothing else. Go's RE2 also folds the Kelvin sign into "k" and the long s into "s". No credential format needs that, and it would let look-alike characters match a prefix.

## D-6. Findings: ranges, the union of overlaps, the specific name

A finding holds the rule's facts and a range, never the value. Overlapping matches become one finding that covers all of them, so a redaction never leaves part of a secret readable. The finding is named by a vendor rule when one is part of it, even if a setting rule matched a wider range: "Atlassian API token" says more than "Secret in a setting".

## D-7. Entropy only where gitleaks has it

keysnitch does not guess random strings by entropy. A minimum entropy is used only as a filter on a rule's own match, with the values gitleaks uses, to skip things like `aaaaaaaa`.

## D-8. Setting rules: a name, then a value that does not read like prose

`password=...`, `JIRA_API_TOKEN=...`, `app_key: ...`, `"clientSecret": "..."` are found by name. The name must end right before the operator, so `passport=` and `tokenUrl=` do not count. After `=`, any value of 6 or more characters counts. After `:` (which prose uses too) the value must have letters together with a digit or a symbol, or be 20 characters or more, so "Credentials: regenerate" and "Docs: id.atlassian.com" are not reported. Types (`password: string`), references (`this.token`) and calls (`getPassword()`) are left out. The price: "1Password" after a colon is reported.

## D-9. Test values are built when tests run

No real-looking key is stored in the repository. Examples are built from parts, or from the rule's own pattern, while the tests run. GitHub push protection and other scanners never see a key-shaped string in the history. `test/repo.test.ts` runs keysnitch over its own source and documents.

## D-10. MIT license

Same as gitleaks and secretlint, whose patterns keysnitch adapts. The owner may change it before the repository goes public.
