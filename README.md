# keysnitch

[![npm](https://img.shields.io/npm/v/keysnitch)](https://www.npmjs.com/package/keysnitch)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16418/badge)](https://www.bestpractices.dev/projects/16418)

Find leaked API keys, tokens and passwords in any text.

keysnitch reads a string and tells you where the credentials are: an Atlassian API token in a Jira comment, a Google API key in a URL, a database password in a pasted `.env` file. It has 250 built-in rules from 129 companies and projects, including every rule of gitleaks v8.30.1 that applies to text.

- **Zero dependencies.** Nothing to audit but this package.
- **Safe on untrusted input.** Every rule passes a safety check before it can run, so no text can make a scan slow (no ReDoS). Scans stay linear in the length of the text.
- **Runs anywhere.** Pure TypeScript with no Node APIs: Node, browsers, workers, serverless and Atlassian Forge.
- **Ranges, not values.** A finding says where the secret is. The value never lands in a finding, an error or a log.
- **Nothing left readable.** When rules overlap, the finding covers all of them.

## Try it

Paste any text, such as a log, a config file, a chat message or a `.env` file, into the free [API key leak checker](https://simplify-software.org/tools/api-key-leak-checker). It runs keysnitch in your browser and sends nothing anywhere.

## Used in

[Secret Sentinel for Jira](https://marketplace.atlassian.com/apps/1051006300) and [Secret Sentinel for Confluence](https://marketplace.atlassian.com/apps/2527876384), Atlassian apps by the same author, redact what keysnitch finds in issues, comments and pages. They test every built-in rule in paragraphs, tables, code blocks, quotes, lists and headings.

## Install

```sh
npm install keysnitch
```

Node 24 or newer.

## Use

```ts
import { readFileSync } from "node:fs";
import { mask, scan } from "keysnitch";

const text = readFileSync("pasted-notes.txt", "utf8");
const { findings, complete } = scan(text);

for (const finding of findings) {
  const value = text.slice(finding.start, finding.end);
  console.log(finding.vendor, finding.label, finding.severity, mask(value));
}
// GitHub  GitHub personal access token  high  ghp_****x9Q2
// Google  Google API key                high  AIza****b7Tk
```

`complete` is false when `maxFindings` stopped the scan early.

### Redact

```ts
let redacted = text;
for (const finding of [...findings].reverse()) {
  redacted = `${redacted.slice(0, finding.start)}[REDACTED ${finding.ruleId}]${redacted.slice(finding.end)}`;
}
```

### Options

```ts
scan(text, {
  rules, // the rules to run, default: all built-in rules
  matchers, // extra matchers written in code (see below)
  maxFindings: 1000, // stop after this many
  ignore: (value, finding) => false, // return true to skip a value, for example one a user marked as safe
});
```

### Find rules by company

For a settings screen:

```ts
import { findRules, vendors } from "keysnitch";

findRules("atlassian"); // every Atlassian rule: API tokens, access tokens, app passwords, ...
findRules("firebase"); // Google rules, through the alias
vendors(); // [{ vendor: "1Password", count: 2 }, ...]
```

### Add your own rule

```ts
import { defineRule, rules, scan } from "keysnitch";

const acme = defineRule({
  id: "acme-api-key",
  vendor: "Acme",
  label: "Acme API key",
  severity: "high",
  keywords: ["acme_"],
  pattern: "\\bacme_[A-Za-z0-9]{32}(?![A-Za-z0-9])",
});

scan(text, { rules: [...rules, acme] });
```

`defineRule` checks the pattern first. A pattern that could make matching slow is refused with `UnsafePatternError`, which lists the problems. Patterns use the RE2 syntax that gitleaks uses; [docs/patterns.md](docs/patterns.md) says what is allowed and why.

### Patterns you cannot check

If the patterns come from your users, run them with an engine that is linear by design (RE2) and plug it in as a custom matcher:

```ts
const custom = {
  id: "my-pattern",
  vendor: "Custom",
  label: "My pattern",
  severity: "medium",
  find: (text: string) => myRe2Matches(text), // returns { start, end } ranges
} as const;

scan(text, { matchers: [custom] });
```

## Rules

[docs/rules.md](docs/rules.md) lists every rule by company. In short:

- every rule of gitleaks v8.30.1 for text (220 of 222; the two left out match file names or guess by entropy), several of them made wider or fixed: see `tools/gitleaks/overrides.ts` and `tools/gitleaks/also.ts`;
- keysnitch's own rules for keys gitleaks misses: Atlassian access tokens and Bitbucket app passwords, Azure Storage keys and SAS signatures, Google OAuth secrets, Groq, xAI, Replicate, Docker Hub, Figma, Supabase and more;
- passwords in URLs, secrets in settings and `.env` files, a password told in a sentence or in the password column of a table, `Authorization: Bearer` and `Basic` headers, `curl -u` and `docker login -p`.

Documentation placeholders (`your_api_key`, `${TOKEN}`, `<secret>`, `xxxx`) are never reported.

## How it compares

We wrote 1,400 fake leaks in 28 shapes, the way people paste them into tickets and wiki pages: an AWS key pair in a comment, a GitHub token in a runbook, a `.env` line, `curl -u`, a Basic auth header, a password in a table or in a sentence. Every value is random and has the vendor's published format (1 Nov 2026).

| Scanner                                                                       | Found |
| ----------------------------------------------------------------------------- | ----: |
| secretlint 13.0.4, recommended rules, plus two rules for JWTs and AWS key IDs |   898 |
| keysnitch 0.1.1                                                               | 1,392 |

Read this with care: keysnitch was written after this test, by people who knew its 28 shapes, so its count is not a blind result. Most of the difference is passwords with no prefix (a `.env` line, `curl -u`, a Basic header, a table, a sentence), which secretlint's recommended rules do not look for, and Atlassian, Google, Telegram and Azure Storage keys.

The 8 keysnitch misses are passwords made only of letters in a table column. It leaves those out on purpose, so that a word like "regenerate" after "Credentials:" is not reported (docs/decisions.md, D-8).

Compared with gitleaks: keysnitch has every gitleaks rule for text, so it finds at least what gitleaks finds by pattern. gitleaks scans git history and files; keysnitch scans a string you give it, in any JavaScript runtime.

## Limits

keysnitch is a safety net, not a guarantee. It finds credentials with a known shape. It does not guess random strings by entropy, so a password with no name next to it, or a token of an unknown format, is not found. Text only: no files, no archives, no images.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Contributing

New key formats are very welcome. [CONTRIBUTING.md](CONTRIBUTING.md) shows how to add one, test first.

## License

MIT. The gitleaks patterns are MIT too, see [NOTICE.md](NOTICE.md).
