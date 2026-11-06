# AGENTS.md: rules for AI agents and people working on keysnitch

keysnitch finds leaked credentials in text. It is a security tool, so its own mistakes matter: a missed key, a finding that leaves part of a key readable, a pattern that can be made slow, a value that leaks into an error. Read this file, `CONVENTIONS.md`, `docs/decisions.md` and `docs/patterns.md` before changing anything. When they disagree, fix whichever is stale in the same change.

## How we work

- **Strict TDD.** Scenario first, one test run and seen failing for the right reason, the least code, refactor on green. No code in `src/` without a test that asked for it.
- **Fast checks before every commit:** `npm run typecheck`, `npm run lint`, `npm run format:check` and the tests you touched. **`npm run check` once at the end of a version** and before every merge.
- **Sequentially.** One test run at a time (`--test-concurrency=2`). No parallel agents.
- **Never stop on a question.** Write it into `PLAN.md` under "Questions for the owner" with the safe default you chose, and continue.

## What must stay true

- **No runtime dependencies.** `test/repo.test.ts` fails if one appears. Dev dependencies are exact versions, at least two weeks old when added.
- **`src/` runs anywhere:** no `node:` imports, no `console`, no `process`, no network, no `eval`.
- **Every RegExp is built in `src/pattern/compile.ts`** after the safety check. ESLint refuses regex literals and `new RegExp` elsewhere in `src/`. Do not weaken `src/pattern/check.ts` to let a rule in: change the rule.
- **A finding never holds the value.** Errors never hold the value or the scanned text.
- **Findings never eat the text around a key** (no closing quote, no `;`). The contract tests check every built-in rule.
- **gitleaks is the floor.** Every rule id of `third_party/gitleaks/gitleaks.toml` is a built-in rule or skipped with a reason (`test/rules/gitleaks-floor.test.ts`). `src/rules/gitleaks.ts` is generated: change `tools/gitleaks/*` and run `node tools/gitleaks/import.ts`.
- **No real-looking key in the repository.** Tests build values from parts while they run.
- **ASCII only in code and tests.** Write other characters as escapes.
- **Coverage stays at 100 %** of lines, branches and functions of `src/`. Unreachable code is removed, not excluded.

## Public API (never break it silently)

The exports of `src/index.ts` (`test/index.test.ts` lists them), the `Finding`, `Rule`, `RuleSpec` and `CustomMatcher` shapes, and the rule ids. A rule id is a public name: users store it (ignore lists, settings). Renaming or removing one is a major version. Adding exports, fields and rules is a minor version.

## Commits and pull requests

Conventional Commits, short and plain (`CONTRIBUTING.md`). The author is the person who owns the work. No AI attribution lines, no mention of tools that wrote the code, no long dashes. One logical change per commit. A pull request per version; until CI runs for this account, merge on a green local `npm run check` and say so in the pull request.

## A change is done when

- its test failed first and passes now, and `npm run check` passes at the end of the version;
- `docs/rules.md` is regenerated if rules changed, and `CHANGELOG.md` has a line under "Unreleased";
- `PLAN.md` is updated (status, questions);
- the public API is unchanged, or changed on purpose with a version bump.
