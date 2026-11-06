// Wider shapes for gitleaks rules, taken from the free checker on
// simplify-software.org (test/fixtures/website-formats.json). gitleaks
// often needs an exact length or a context word; real keys of these
// vendors also come in other lengths and alone. The importer adds each
// shape as a second branch of the gitleaks rule, so the rule keeps one id
// and one name. Every shape ends with a lookahead, so the character after
// the key is never part of the finding.

export interface AlsoShape {
  readonly pattern: string;
  readonly keywords: readonly string[];
}

export const ALSO: Readonly<Record<string, AlsoShape>> = {
  "aws-access-token": {
    pattern: String.raw`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[0-9A-Z]{16}(?![0-9A-Za-z])`,
    keywords: ["akia", "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "a3t"],
  },
  // Shapes the secretlint recommended preset finds and gitleaks does not.
  "github-app-token": {
    pattern: String.raw`\bghs_[0-9]{1,20}_[A-Za-z0-9_-]{1,1000}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,1000}(?![A-Za-z0-9_-])`,
    keywords: ["ghs_"],
  },
  "shopify-access-token": {
    pattern: String.raw`\bshp(?:at|ca|pa|ss)_[a-zA-Z0-9]{32,64}(?![a-zA-Z0-9])`,
    keywords: ["shpat_", "shpca_", "shppa_", "shpss_"],
  },
  "sendgrid-api-token": {
    pattern: String.raw`\bSG\.[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{16,128}(?![A-Za-z0-9_-])`,
    keywords: ["sg."],
  },
  "github-fine-grained-pat": {
    pattern: String.raw`\bgithub_pat_[A-Za-z0-9_]{60,255}(?![A-Za-z0-9_])`,
    keywords: ["github_pat_"],
  },
  "anthropic-api-key": {
    pattern: String.raw`\bsk-ant-[A-Za-z0-9_-]{20,200}(?![A-Za-z0-9_-])`,
    keywords: ["sk-ant-"],
  },
  "openai-api-key": {
    pattern: String.raw`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,200}(?![A-Za-z0-9_-])`,
    keywords: ["sk-"],
  },
  "slack-legacy-token": {
    pattern: String.raw`\bxox[abposr]-[A-Za-z0-9-]{10,200}(?![A-Za-z0-9-])`,
    keywords: ["xox"],
  },
  "slack-webhook-url": {
    pattern: String.raw`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,200}(?![A-Za-z0-9/])`,
    keywords: ["hooks.slack.com"],
  },
  "gitlab-pat": { pattern: String.raw`\bglpat-[A-Za-z0-9_-]{20,128}(?![A-Za-z0-9_-])`, keywords: ["glpat-"] },
  "perplexity-api-key": {
    pattern: String.raw`\bpplx-[A-Za-z0-9]{40,100}(?![A-Za-z0-9])`,
    keywords: ["pplx-"],
  },
  "vault-service-token": {
    pattern: String.raw`\bhv[sbr]\.[A-Za-z0-9_-]{24,300}(?![A-Za-z0-9_-])`,
    keywords: ["hvs.", "hvb.", "hvr."],
  },
  "sentry-org-token": {
    pattern: String.raw`\bsntrys_[A-Za-z0-9_=+/.-]{40,400}(?![A-Za-z0-9_=+/.-])`,
    keywords: ["sntrys_"],
  },
  "sentry-user-token": {
    pattern: String.raw`\bsntryu_[A-Za-z0-9_=+/.-]{40,400}(?![A-Za-z0-9_=+/.-])`,
    keywords: ["sntryu_"],
  },
  "new-relic-user-api-key": { pattern: String.raw`\bNRAK-[A-Z0-9]{27}(?![A-Z0-9])`, keywords: ["nrak-"] },
  "microsoft-teams-webhook": {
    pattern: String.raw`https://[a-z0-9-]{1,100}\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/-]{40,600}(?![A-Za-z0-9@/-])`,
    keywords: ["webhook.office.com"],
  },
  jwt: {
    pattern: String.raw`\beyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}(?![A-Za-z0-9_-])`,
    keywords: ["eyj"],
  },
};
