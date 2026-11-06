// Hand-written changes to gitleaks rules that do not pass the safety check
// as they are, or whose capture groups would report the wrong text, and
// gitleaks rules keysnitch does not import. Each entry says why.

export interface Override {
  readonly pattern?: string;
  readonly keywords?: readonly string[];
  readonly allow?: readonly string[];
  readonly secretGroup?: number;
  readonly reason: string;
}

// "user:secret" after curl -u, or after a header, within 500 characters of
// the word curl (line continuations included).
const CURL = String.raw`\bcurl\b[\s\S]{0,500}?[ \t\r\n]`;

// gitleaks' common shape for "name = value": the name, up to 20 more name
// characters, an operator, and up to 5 quote or space characters.
const NAMED = String.raw`(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}`;
const END = String.raw`(?:[\x60'"\s;]|\\[nr]|$)`;

export const OVERRIDES: Readonly<Record<string, Override>> = {
  "atlassian-api-token": {
    pattern: String.raw`(?i)(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))${NAMED}([a-z0-9]{20}[a-f0-9]{4})${END}|\b((?-i:ATATT)[A-Za-z0-9_=-]{100,400})(?![A-Za-z0-9_=-])`,
    keywords: ["atlassian", "confluence", "jira", "atatt"],
    reason:
      "Atlassian says the token length varies and documents the prefix ATAT: any length from 100 to 400 after ATATT, not exactly 186 after ATATT3; the end is a lookahead, so a token before & or ) is found too",
  },
  "sourcegraph-access-token": {
    pattern: String.raw`\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})(?![A-Za-z0-9_])|(?i:sourcegraph|src_access_token)${NAMED}([a-fA-F0-9]{40})${END}`,
    keywords: ["sgp_", "sourcegraph", "src_access_token"],
    reason:
      "gitleaks takes any 40 hex characters once the text says sourcegraph anywhere, so every git commit hash there is a token; an old token without the sgp_ prefix now needs its name next to it",
  },
  "gcp-api-key": {
    pattern: String.raw`\b(AIza[\w-]{35})(?![\w-])`,
    reason:
      "the end is a lookahead: gitleaks needs a quote, space or ; after the key and misses it in a URL before &",
  },
  "telegram-bot-api-token": {
    pattern: String.raw`(?i)(?:telegr)${NAMED}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})${END}|\b([0-9]{8,10}:(?-i:AA)[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])`,
    keywords: ["telegr", ":aa"],
    reason:
      "also finds a bot token without the word telegram next to it (bot id, a colon, AA and 33 characters)",
  },
  "mailgun-private-api-token": {
    pattern: String.raw`(?i)(?:mailgun)${NAMED}(key-[a-f0-9]{32})${END}|\b((?-i:key-)[a-f0-9]{32})(?![A-Za-z0-9])`,
    keywords: ["mailgun", "key-"],
    reason: "also finds a key-... value without the word mailgun next to it",
  },
  "huggingface-access-token": {
    pattern: String.raw`\b(hf_[A-Za-z0-9]{34,100})(?![A-Za-z0-9])`,
    reason: "Hugging Face tokens hold digits too; gitleaks takes letters only",
  },
  "doppler-api-token": {
    pattern: String.raw`\b(dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9_-]{40,60})(?![A-Za-z0-9_-])`,
    keywords: ["dp.pt.", "dp.st.", "dp.ct.", "dp.sa.", "dp.scim.", "dp.audit."],
    reason:
      "all Doppler token types (personal, service, CLI, service account, SCIM, audit), not only personal",
  },
  "sentry-org-token": {
    pattern: String.raw`\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?![a-zA-Z0-9+/])`,
    reason:
      "the end check is a lookahead, so the character after the token is not part of the finding (gitleaks reports it, and a redaction would eat a closing quote)",
  },
  "airtable-personnal-access-token": {
    keywords: ["airtable", "pat"],
    reason: "the token starts with pat, so it is found without the word airtable next to it",
  },
  "slack-user-token": {
    pattern: String.raw`xox[pe]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]{28,34}`,
    reason:
      "the group repeated 3 times is written out 3 times (a repeated part must have a fixed length); same meaning",
  },
  "microsoft-teams-webhook": {
    pattern: String.raw`https://[a-z0-9]{1,100}\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}`,
    secretGroup: 0,
    reason:
      "the UUID parts are not capture groups, so the whole URL is the secret (in gitleaks the first group, 5 characters, was reported)",
  },
  "jwt-base64": {
    pattern: String.raw`\bZXlK(?:aGJHY2lPaU|aGNIVWlPaU|aGNIWWlPaU|aGRXUWlPaU|aU5qUWlP|amNtbDBJanBi|amRIa2lPaU|bGNHc2lPbn|bGJtTWlPaU|cWEzVWlPaU|cWQyc2lPb|cGMzTWlPaU|cGRpSTZJ|cmFXUWlP|clpYbGZiM0J6SWpwY|cmRIa2lPaUp|dWIyNWpaU0k2|d01tTWlP|d01uTWlPaU|d2NIUWlPaU|emRXSWlPaU|emRuUWlP|MFlXY2lPaU|MGVYQWlPaUp|MWNtd2l|MWMyVWlPaUp|MlpYSWlPaU|MlpYSnphVzl1SWpv|NElqb2|NE5XTWlP|NE5YUWlPaU|NE5YUWpVekkxTmlJNkl|NE5YVWlPaU|NmFYQWlPaU)[a-zA-Z0-9/\\_+\-\r\n]{40,2048}={0,2}`,
    secretGroup: 0,
    reason:
      "the header names are not capture groups, so the whole token is the secret (in gitleaks the first group, a header name, was reported); the body is bounded at 2048 characters",
  },
  "curl-auth-user": {
    pattern: `${CURL}(?:-u|--user)(?:=|[ \\t]{1,5})(?:"([^":\\s]{1,200}:[^"\\s]{3,200})"|'([^':\\s]{1,200}:[^'\\s]{3,200})'|([^\\s"':]{1,200}:[^\\s"']{3,200}))`,
    allow: [
      String.raw`^[^:]{1,200}:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*{1,200}|x{1,200})$`,
      String.raw`^<[^>]{1,200}>:<[^>]{1,200}>$`,
      String.raw`:\$`,
      String.raw`^\$`,
    ],
    reason:
      "gitleaks allows any number of lines between curl and -u with nested unbounded repeats; keysnitch looks 500 characters ahead (line breaks included) and takes user:secret in quotes or bare",
  },
  "curl-auth-header": {
    pattern: `${CURL}(?:-H|--header)(?:=|[ \\t]{1,5})["'](?i:authorization:[ \\t]{0,5}(?:basic[ \\t]{1,5}([a-z0-9+/]{8,4096}={0,3})|(?:bearer|(?:api-)?token)[ \\t]{1,5}([\\w=~@.+/-]{8,4096})|([\\w=~@.+/-]{8,4096}))|(?:x-[a-z]{1,40}-)?(?:api-?)?(?:key|token):[ \\t]{0,5}([\\w=~@.+/-]{8,4096}))`,
    reason:
      "same 500 character look-ahead as curl-auth-user instead of nested unbounded repeats; the header shapes are those of gitleaks",
  },
  "kubernetes-secret-yaml": {
    pattern: String.raw`(?i)\bkind:[ \t]{0,20}["']?secret\b["']?[\s\S]{0,300}?\bdata:[ \t]{0,20}\r?\n[ \t]{1,20}[\w.-]{1,100}:[ \t]{1,20}["']?([a-z0-9+/]{10,4096}={0,3})["']?`,
    allow: [],
    reason:
      "a Secret manifest with kind before data, the first data value is the secret (only base64 text, so the gitleaks allowlist for template values is not needed) (gitleaks also allows data before kind and reports the key name with the value); bounded look-ahead of 300 characters",
  },
};

/** gitleaks rules that keysnitch does not import, with the reason. */
export const SKIPPED: Readonly<Record<string, string>> = {
  "pkcs12-file": "matches a file name (*.p12), not text; keysnitch scans text only",
  "generic-api-key":
    "an entropy guess over any 'key = value'; replaced by keysnitch's own rules for named settings (generic-*)",
};
