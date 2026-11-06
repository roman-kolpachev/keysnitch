# Conventions

Only rules a tool cannot check live here. Everything else is in `tsconfig.json`, `eslint.config.mjs`, Prettier and `test/repo.test.ts`.

## Tests

- A test file starts with its scenarios, in plain words.
- Assert behaviour: what `scan()` returns for a text. Not which helper was called.
- Test values are built from parts (`chars()` in the rule tests, `sample()` from a pattern). Never paste a real key, not even a revoked one.
- Every edge case gets a test: empty text, one character, the end of the text, line endings, Unicode spaces, zero-width characters, emoji before a key, quotes and brackets around it, a key glued to more characters.
- Slow input is a test too: build it from the rule's own pieces and give it a time budget.

## Code

- No type assertions (`as const` only), no `!`, no `any`, no `@ts-` comments, no `eslint-disable`. Untrusted data is `unknown` and is narrowed by a guard.
- Pure functions. No state between calls. Frozen exports.
- A comment says why, not what.
- Names say what a thing is, in plain English.

## Rules

- `id` is kebab-case and stable. Where a gitleaks rule exists, its id.
- `keywords` are lower case and appear in every text the rule can match (the contract tests check it).
- End a key with a lookahead, not `\b` and not a consumed character (`docs/patterns.md`).
- Every rule says where to rotate the key (`rotate`) when the vendor documents it.

## Writing

Short sentences. Plain words. No long dashes: use a comma, a period or brackets.
