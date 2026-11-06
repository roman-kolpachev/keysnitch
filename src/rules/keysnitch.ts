// keysnitch's own rules: credentials that gitleaks does not cover, or covers
// only with a context word next to them. Shapes follow the vendors'
// published prefixes. Every pattern passes the same safety check as any
// other rule (see src/pattern/check.ts).

import type { RuleSpec } from "../types.ts";

const KEY_END = String.raw`(?![A-Za-z0-9_-])`;

// Names of settings that hold a secret. The name must end right before the
// operator, so "passport=" or "tokenUrl=" do not count.
const SETTING_NAMES = String.raw`(?:pass(?:word|wd)?|pwd|secret|token|(?:api|app|secret|private|access|client|consumer|encryption|signing|master|license|auth)[_.-]?key|apikey|client[_.-]?secret|app[_.-]?secret|consumer[_.-]?secret|auth|credentials?)`;
const SETTING_KEYWORDS = ["pass", "pwd", "secret", "token", "key", "auth", "credential"];
const SETTING_ALIASES = [".env", "environment variable", "app key", "app secret", "client secret"];
const SETTING_ROTATE =
  "Change the password or revoke the key, then keep it in a secrets manager instead of the text.";
const SETTING_ALLOW = [
  // Types in code: password: string, (secret: string) =>, token?: string | null.
  // A whole word only: "stringent2024" is still a password.
  String.raw`^(?:string|number|boolean|bool|int|integer|str|text|varchar|char|bytes|object|any|unknown|optional|required|secret|password|token|undefined|none)\b`,
  // References: token: this.token, password = config.db.password.
  String.raw`^(?:this|self|props|state|config|env|process|options|opts|args|params|data|req|request|ctx|context|settings|os|sys|vars|secrets)\.`,
  // Calls: getPassword(), getSecret(name), os.getenv( before a quote,
  // text.slice(start before a comma. A password may hold brackets, so text
  // after the closing bracket ("abc(1)xyz") is not a call.
  String.raw`^[A-Za-z_$][A-Za-z0-9_$.]{0,100}\([^)]{0,200}\)?$`,
  // An address is an endpoint, not a secret (a password in it is found by url-credentials).
  String.raw`^[A-Za-z][A-Za-z0-9+.-]{1,20}://`,
];

const ATLASSIAN = ["Jira", "Confluence", "Bitbucket", "Trello"];
const GOOGLE = ["GCP", "Google Cloud", "Firebase", "Gemini"];
const MICROSOFT = ["Azure", "Entra", "Teams", "Office 365"];

export const keysnitchRules: readonly RuleSpec[] = [
  // Atlassian. Atlassian documents the prefixes ATAT (API tokens), ATCT
  // (access tokens) and ATBB (app passwords); the token length varies.
  {
    id: "atlassian-access-token",
    vendor: "Atlassian",
    label: "Atlassian access token (workspace, project, repository or admin)",
    severity: "high",
    keywords: ["atctt"],
    pattern: String.raw`\bATCTT[A-Za-z0-9_=-]{100,400}(?![A-Za-z0-9_=-])`,
    aliases: ATLASSIAN,
    rotate:
      "Revoke it where it was made: Bitbucket repository, project or workspace settings, Access tokens; or admin.atlassian.com, API keys.",
  },
  {
    id: "bitbucket-app-password",
    vendor: "Atlassian",
    label: "Bitbucket app password",
    severity: "high",
    keywords: ["atbb"],
    pattern: String.raw`\bATBB[A-Za-z0-9_=-]{28,64}(?![A-Za-z0-9_=-])`,
    aliases: ATLASSIAN,
    rotate: "Bitbucket, Personal settings, App passwords: revoke it.",
  },

  // Google.
  {
    id: "google-oauth-client-secret",
    vendor: "Google",
    label: "Google OAuth client secret",
    severity: "high",
    keywords: ["gocspx-"],
    pattern: String.raw`\bGOCSPX-[A-Za-z0-9_-]{28}${KEY_END}`,
    aliases: GOOGLE,
    rotate: "Google Cloud console, Credentials, the OAuth client: reset the secret.",
  },

  // Microsoft.
  {
    id: "azure-storage-account-key",
    vendor: "Microsoft",
    label: "Azure Storage account key",
    severity: "high",
    keywords: ["accountkey"],
    pattern: String.raw`(?i:AccountKey)=([A-Za-z0-9+/]{86}==)`,
    aliases: MICROSOFT,
    rotate: "Azure portal, the storage account, Access keys: rotate the key.",
  },
  {
    id: "azure-sas-token",
    vendor: "Microsoft",
    label: "Azure shared access signature",
    severity: "high",
    keywords: ["sig="],
    pattern: String.raw`\bsv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&[^\s"'<>]{0,500}?\bsig=([A-Za-z0-9%+/]{30,120})`,
    aliases: MICROSOFT,
    rotate: "Rotate the storage account key the signature was made with, or revoke its stored access policy.",
  },

  // AI services.
  {
    id: "groq-api-key",
    vendor: "Groq",
    label: "Groq API key",
    severity: "high",
    keywords: ["gsk_"],
    pattern: String.raw`\bgsk_[A-Za-z0-9]{48,300}(?![A-Za-z0-9])`,
    rotate: "Groq Console, API Keys: delete the key.",
  },
  {
    id: "xai-api-key",
    vendor: "xAI",
    label: "xAI API key",
    severity: "high",
    keywords: ["xai-"],
    pattern: String.raw`\bxai-[A-Za-z0-9]{70,200}(?![A-Za-z0-9])`,
    aliases: ["Grok"],
    rotate: "xAI Console, API Keys: delete the key.",
  },
  {
    id: "replicate-api-token",
    vendor: "Replicate",
    label: "Replicate API token",
    severity: "high",
    keywords: ["r8_"],
    pattern: String.raw`\br8_[A-Za-z0-9]{37}(?![A-Za-z0-9])`,
    rotate: "Replicate, Account, API tokens: delete the token.",
  },

  // AWS. gitleaks finds key ids (AKIA...); the secret key has no prefix,
  // so it is found by the setting name next to it, like secretlint does.
  {
    id: "aws-secret-access-key",
    vendor: "AWS",
    label: "AWS secret access key",
    severity: "high",
    keywords: ["secret"],
    pattern: String.raw`(?:AWS|aws|Aws)?_?(?:SECRET|secret|Secret)_?(?:ACCESS|access|Access)_?(?:KEY|key|Key)["']?\s{0,20}(?::|=>|=)\s{0,20}["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])`,
    aliases: ["Amazon", "Amazon Web Services", "IAM"],
    rotate: "AWS IAM console, Users, Security credentials: deactivate, then delete the access key.",
  },
  {
    id: "aws-account-id",
    vendor: "AWS",
    label: "AWS account ID",
    severity: "low",
    keywords: ["account"],
    pattern: String.raw`(?:AWS|aws|Aws)?_?(?:ACCOUNT|account|Account)_?(?:ID|id|Id)?["']?\s{0,20}(?::|=>|=)\s{0,20}["']?([0-9]{4}-?[0-9]{4}-?[0-9]{4})(?![0-9])`,
    aliases: ["Amazon", "Amazon Web Services"],
  },

  // Developer platforms.
  {
    id: "tailscale-key",
    vendor: "Tailscale",
    label: "Tailscale key",
    severity: "high",
    keywords: ["tskey-"],
    pattern: String.raw`\btskey-[a-z]{2,20}-[0-9A-Za-z_]{8,40}-[0-9A-Za-z_]{16,60}(?![0-9A-Za-z_])`,
    rotate: "Tailscale admin console, Settings, Keys: revoke the key.",
  },
  {
    id: "vercel-token",
    vendor: "Vercel",
    label: "Vercel token",
    severity: "high",
    keywords: ["vcp_", "vci_", "vca_", "vcr_", "vck_"],
    pattern: String.raw`\b(?:vcp|vci|vca|vcr|vck)_[A-Za-z0-9]{20,60}(?![A-Za-z0-9])`,
    rotate: "Vercel, Account settings, Tokens: delete the token.",
  },
  {
    id: "cloudflare-api-token",
    vendor: "Cloudflare",
    label: "Cloudflare API token or key (new format)",
    severity: "high",
    keywords: ["cfk_", "cfut_", "cfat_"],
    pattern: String.raw`\b(?:cfk|cfut|cfat)_[A-Za-z0-9]{40}[0-9a-f]{8}(?![A-Za-z0-9])`,
    rotate: "Cloudflare dashboard, My Profile or Account, API Tokens: roll or delete the token.",
  },
  {
    id: "docker-hub-access-token",
    vendor: "Docker",
    label: "Docker Hub access token",
    severity: "high",
    keywords: ["dckr_"],
    pattern: String.raw`\bdckr_(?:pat|oat)_[A-Za-z0-9_-]{27,200}${KEY_END}`,
    aliases: ["Docker Hub"],
    rotate: "Docker Hub, Account settings, Personal access tokens: delete the token.",
  },
  {
    id: "figma-access-token",
    vendor: "Figma",
    label: "Figma personal access token",
    severity: "high",
    keywords: ["figd_"],
    pattern: String.raw`\bfigd_[A-Za-z0-9_-]{40,200}${KEY_END}`,
    rotate: "Figma, Settings, Security, Personal access tokens: revoke it.",
  },
  {
    id: "supabase-access-token",
    vendor: "Supabase",
    label: "Supabase access token",
    severity: "high",
    keywords: ["sbp_"],
    pattern: String.raw`\bsbp_[a-f0-9]{40}(?![A-Za-z0-9])`,
    rotate: "Supabase, Account, Access Tokens: revoke the token.",
  },
  {
    id: "supabase-secret-key",
    vendor: "Supabase",
    label: "Supabase secret API key",
    severity: "high",
    keywords: ["sb_secret_"],
    pattern: String.raw`\bsb_secret_[A-Za-z0-9_-]{20,60}${KEY_END}`,
    rotate: "Supabase, Project settings, API Keys: delete the secret key and create a new one.",
  },
  {
    id: "square-oauth-secret",
    vendor: "Square",
    label: "Square OAuth secret",
    severity: "high",
    keywords: ["sq0csp-"],
    pattern: String.raw`\bsq0csp-[A-Za-z0-9_-]{43}${KEY_END}`,
    rotate: "Square Developer Dashboard, OAuth: replace the application secret.",
  },
  {
    id: "mapbox-secret-token",
    vendor: "Mapbox",
    label: "Mapbox secret token",
    severity: "high",
    keywords: ["sk.eyj"],
    pattern: String.raw`\bsk\.eyJ[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{20,100}${KEY_END}`,
    rotate: "Mapbox, Tokens: delete the token.",
  },
  {
    id: "notion-legacy-integration-token",
    vendor: "Notion",
    label: "Notion integration token (old format)",
    severity: "high",
    keywords: ["secret_"],
    pattern: String.raw`\bsecret_[A-Za-z0-9]{43}(?![A-Za-z0-9])`,
    rotate: "Notion, Settings, Integrations: refresh the secret.",
  },
  {
    id: "discord-webhook-url",
    vendor: "Discord",
    label: "Discord webhook URL",
    severity: "high",
    keywords: ["discord"],
    pattern: String.raw`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{1,30}/[A-Za-z0-9_-]{60,100}${KEY_END}`,
    rotate: "Discord, Server settings, Integrations, Webhooks: delete it.",
  },

  // Credentials in text that are not tied to one company.
  {
    id: "url-credentials",
    vendor: "Generic",
    label: "Password in a URL",
    severity: "high",
    keywords: ["://"],
    pattern: String.raw`\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@"'<>]{1,200}:([^\s@/"'<>]{3,200})@[A-Za-z0-9.-]{1,253}`,
    allow: [String.raw`^(?:password|pass|pwd|secret|changeme|\*{1,200})$`],
    generic: true,
    aliases: ["connection string", "database URL", "PostgreSQL", "MySQL", "MongoDB", "Redis"],
    rotate: "Change that account's password and keep it in a secrets manager, not in the URL.",
  },
  {
    id: "generic-secret-assignment",
    vendor: "Generic",
    label: "Secret in a setting (password, token, key)",
    severity: "medium",
    keywords: SETTING_KEYWORDS,
    pattern: String.raw`(?i)${SETTING_NAMES}["']?\s{0,40}(?::=|=>|=)\s{0,40}["'\x60]?([^\s"'\x60,;]{6,200})`,
    allow: SETTING_ALLOW,
    generic: true,
    aliases: SETTING_ALIASES,
    rotate: SETTING_ROTATE,
  },
  {
    // "Password: ..." is also how people write prose, so after a colon the
    // value must look random: a digit, a symbol, a capital letter inside,
    // or 20 characters or more. "Credentials: regenerate" is not reported.
    id: "generic-secret-colon",
    vendor: "Generic",
    label: "Secret after a name and a colon (YAML, JSON, notes)",
    severity: "medium",
    keywords: SETTING_KEYWORDS,
    pattern: String.raw`(?i)${SETTING_NAMES}["']?\s{0,40}:(?!=)\s{0,40}["'\x60]?([^\s"'\x60,;]{6,200})`,
    allow: SETTING_ALLOW,
    validate: looksRandom,
    generic: true,
    aliases: SETTING_ALIASES,
    rotate: SETTING_ROTATE,
  },
  {
    id: "generic-env-secret",
    vendor: "Generic",
    label: "Secret in an environment variable export",
    severity: "medium",
    keywords: ["export", "set "],
    pattern: String.raw`(?i)\b(?:export|set)[ \t]{1,5}[A-Z0-9_]{0,60}(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|APP_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH)[A-Z0-9_]{0,20}[ \t]{0,5}=[ \t]{0,5}["']?([^\s"';]{6,200})`,
    generic: true,
    aliases: [".env", "shell", "environment variable"],
    rotate: "Change the password or revoke the key, then load it from a secrets manager.",
  },
  {
    id: "generic-bearer-token",
    vendor: "Generic",
    label: "Bearer token in an Authorization header",
    severity: "high",
    keywords: ["bearer"],
    pattern: String.raw`(?i)\bbearer[ \t]{1,5}([A-Za-z0-9._~+/-]{20,4096}={0,2})(?![A-Za-z0-9._~+/=-])`,
    generic: true,
    aliases: ["Authorization header", "OAuth"],
    rotate: "Revoke the token where it was issued.",
  },
  {
    id: "generic-basic-auth",
    vendor: "Generic",
    label: "Basic authentication header (user and password)",
    severity: "high",
    keywords: ["basic"],
    pattern: String.raw`(?i)\bbasic[ \t]{1,5}([A-Za-z0-9+/]{8,400}={0,2})(?![A-Za-z0-9+/=])`,
    validate: isEncodedUserAndSecret,
    generic: true,
    aliases: ["Authorization header"],
    rotate: "Change that account's password; the header holds it in Base64, which is not encryption.",
  },
  {
    id: "docker-login-password",
    vendor: "Docker",
    label: "Password in docker login",
    severity: "high",
    keywords: ["docker"],
    pattern: String.raw`\bdocker[ \t]{1,5}login\b[^\n]{0,200}?[ \t](?:-p|--password)(?:=|[ \t]{1,5})["']?([^\s"';]{4,200})`,
    aliases: ["Docker Hub", "registry"],
    rotate: "Change the registry password or revoke the token, and use --password-stdin.",
  },
];

// Symbols that words, brand names and addresses use too.
const SOFT_SYMBOLS = ".-_/:";

/**
 * True when a value does not read like a word, a brand name or an address:
 * 20 characters or more, or letters together with a digit or with a symbol
 * other than . - _ / and :.
 */
export function looksRandom(value: string): boolean {
  if (value.length >= 20) return true;
  let letter = false;
  let digit = false;
  let symbol = false;
  for (let index = 0; index < value.length; index += 1) {
    const c = value.charCodeAt(index);
    if ((c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a)) letter = true;
    else if (c >= 0x30 && c <= 0x39) digit = true;
    else if (!SOFT_SYMBOLS.includes(value.charAt(index))) symbol = true;
  }
  return letter && (digit || symbol);
}

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Decodes standard Base64 into Latin-1 text, or returns undefined. No dependencies, no atob. */
export function decodeBase64(value: string): string | undefined {
  if (value.length % 4 !== 0) return undefined;
  const body = value.endsWith("==") ? value.slice(0, -2) : value.endsWith("=") ? value.slice(0, -1) : value;
  let bits = 0;
  let buffer = 0;
  let out = "";
  for (let index = 0; index < body.length; index += 1) {
    const digit = BASE64.indexOf(body.charAt(index));
    if (digit === -1) return undefined;
    buffer = (buffer << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }
  return out;
}

/** True when a Base64 value decodes to printable "user:secret" with a secret of 3 or more characters. */
export function isEncodedUserAndSecret(value: string): boolean {
  const decoded = decodeBase64(value);
  if (decoded === undefined) return false;
  for (let index = 0; index < decoded.length; index += 1) {
    const unit = decoded.charCodeAt(index);
    if (unit < 0x20 || unit > 0x7e) return false;
  }
  const colon = decoded.indexOf(":");
  return colon > 0 && decoded.length - colon - 1 >= 3;
}
