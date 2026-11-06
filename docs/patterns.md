# Rule patterns

Rules are written in the RE2 syntax that gitleaks uses. keysnitch parses every pattern itself (`src/pattern/parse.ts`), checks it (`src/pattern/check.ts`) and only then builds a JavaScript `RegExp` from it (`src/pattern/compile.ts`, the only file allowed to do that).

## What you can write

| Syntax                                                | Meaning                                                                                         |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `abc`, `\.`, `\-`, `\x60`, `\x{41}`, `\t \n \r \f \v` | literal characters                                                                              |
| `[a-z0-9_-]`, `[^"']`, `[[:alnum:]]`                  | character classes, POSIX classes inside them                                                    |
| `\d \w \s` and `\D \W \S`                             | digits and word characters are ASCII; `\s` also takes Unicode spaces such as the no-break space |
| `.`                                                   | any character except a line feed; with `(?s)` any character                                     |
| `(...)`, `(?:...)`, `(?P<name>...)`, `(?<name>...)`   | groups                                                                                          |
| `a\|b`                                                | alternation                                                                                     |
| `?`, `{n}`, `{n,m}`, lazy `??` and `{n,m}?`           | repeats with an upper bound                                                                     |
| `^`, `$`, `\A`, `\z`                                  | start and end of the whole text                                                                 |
| `\b`, `\B`                                            | word boundary (ASCII)                                                                           |
| `(?i)`, `(?i:...)`, `(?-i:...)`, `(?s)`               | case folding (ASCII only) and dot-all                                                           |
| `(?![A-Za-z0-9])`, `(?=;\|$)`                         | a lookahead of single characters, to end a key                                                  |

## What the parser refuses

Backreferences, lookbehind, atomic groups, comments, `\p{...}`, `\Q...\E`, unknown escapes and flags, empty groups, a repeat with nothing to repeat, counts above 100000, patterns longer than 10000 characters. A refused pattern throws `PatternError` with the position.

## What the safety check refuses

The built-in RegExp engine backtracks. Backtracking is only slow when a pattern lets the engine try many ways to split the same text, so the check refuses those shapes:

1. **Every repeat has an upper bound**, at most 4096. `+`, `*` and `{n,}` are refused. Write `{1,200}`.
2. **A repeat that can run more than once has a body of fixed length.** `(a+)+`, `(?:a|aa){1,9}` and `(?:[a-z]{2,3}-){2}` are refused; `(?:[0-9a-f]{4}-){3}` is fine. An optional group (`?`) may hold anything.
3. **A lookahead holds only single characters or the end of text.**
4. **A rule never matches empty text.**
5. **The cost estimate stays at or below 100000.** The cost is the steps of every part, plus, for each chain of neighbours that can trade characters, the product of the number of lengths each part can take. `[a-z]{1,10}[a-z]{1,10}` costs 20 + 10 x 10. `[a-z]{1,10}[0-9]` costs 11: a letter can never be given to the digit.

A refused pattern throws `UnsafePatternError` with every problem it found.

## Ending a key

Use a lookahead, not `\b`, to say where a key ends: `\bsk-[A-Za-z0-9-]{32,200}(?![A-Za-z0-9-])`. `\b` never fires after a trailing `-`, so a key that ends with a dash would be missed.

Do not consume the character after the key (`(?:[\s"';]|$)` outside a group): the finding would take the closing quote with it, and a redaction would break the text around the key. The contract tests check this for every built-in rule.
