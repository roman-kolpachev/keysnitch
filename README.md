# keysnitch

Find leaked API keys, tokens and passwords in any text.

keysnitch reads a string and tells you where the credentials are: an Atlassian API token in a Jira comment, a Google API key in a URL, a database password in a pasted `.env` file. It has 243 built-in rules from 127 companies and projects, including every rule of gitleaks v8.30.1 that applies to text.

- **Zero dependencies.** Nothing to audit but this package.
- **Safe on untrusted input.** Every rule passes a safety check before it can run, so no text can make a scan slow (no ReDoS). Scans stay linear in the length of the text.
- **Runs anywhere.** Pure TypeScript with no Node APIs: Node, browsers, workers, serverless and Atlassian Forge.
- **Ranges, not values.** A finding says where the secret is. The value never lands in a finding, an error or a log.
- **Nothing left readable.** When rules overlap, the finding covers all of them.

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
- passwords in URLs, secrets in settings and `.env` files, `Authorization: Bearer` and `Basic` headers, `curl -u` and `docker login -p`.

Documentation placeholders (`your_api_key`, `${TOKEN}`, `<secret>`, `xxxx`) are never reported.

## Limits

keysnitch is a safety net, not a guarantee. It finds credentials with a known shape. It does not guess random strings by entropy, so a password with no name next to it, or a token of an unknown format, is not found. Text only: no files, no archives, no images.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Contributing

New key formats are very welcome. [CONTRIBUTING.md](CONTRIBUTING.md) shows how to add one, test first.

## License

MIT. The gitleaks patterns are MIT too, see [NOTICE.md](NOTICE.md).
