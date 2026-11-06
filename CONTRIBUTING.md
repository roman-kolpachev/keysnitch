# Contributing to keysnitch

Thank you for helping. New key formats, false positive reports and fixes are all welcome.

## Setup

You need Node 24 or newer.

```sh
git clone https://github.com/roman-kolpachev/keysnitch.git
cd keysnitch
npm ci --ignore-scripts
npm run check
```

`npm run check` runs everything CI runs: types, lint, format, tests with the 100 % coverage gate, the build and a dry run of `npm pack`.

While you work, the fast loop is:

```sh
npm run typecheck && npm run lint && node --test test/the-file.test.ts
```

## How we work: test first

1. Write the scenario at the top of the test file, in plain words.
2. Write one test, run it and see it fail for the right reason.
3. Write the least code that makes it pass.
4. Clean up while the tests stay green.

A change without a test that failed first is not done.

## Adding a key format

1. Find the vendor's documentation of the format: prefix, length, characters, checksum. Link it in the issue or the pull request. No guessing.
2. Add a test in `test/rules/keysnitch-rules.test.ts` first:
   - the key alone, in quotes, in JSON, in a URL query and in a `.env` line is found, and the finding is exactly the key;
   - a documentation example or placeholder is not found;
   - a look-alike (same prefix, too short, glued to more letters) is not found.
     Build the value from parts in the test (see the `chars` helper). Never commit a real key, and never a value that looks like one.
3. Add the rule to `src/rules/keysnitch.ts` with `id`, `vendor`, `label`, `severity`, `keywords`, `pattern` and `rotate`. Patterns must pass the safety check, see [docs/patterns.md](docs/patterns.md).
4. Run `node tools/rules-doc.ts` to update `docs/rules.md`.
5. The contract tests (`test/rules/contract.test.ts`) then also check your rule on its own examples and on slow input.

If the format is a gitleaks rule that is too narrow, add a wider shape in `tools/gitleaks/also.ts` instead, then run `node tools/gitleaks/import.ts`.

## Reporting a false positive

Open an issue with the "False positive" template. Remove anything private from the text first.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/): `feat(rules): find Acme API keys`, `fix(pattern): ...`, `docs: ...`, `test: ...`, `chore: ...`.
- The subject is short, in the imperative, lower case after the type.
- The body says why, when that is not obvious. Plain words.
- One logical change per commit, with its tests.

## Pull requests

One topic per pull request. Fill in the template. Add a line to `CHANGELOG.md` under "Unreleased".

## Security issues

Please do not open an issue for a vulnerability. See [SECURITY.md](SECURITY.md).
