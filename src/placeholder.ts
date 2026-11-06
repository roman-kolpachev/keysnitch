// Values that look like a credential's place but are never one: template
// variables, environment lookups, "your_key_here" and friends. Every rule
// skips them. The patterns go through the same safety check as rules.

import { compile } from "./pattern/compile.ts";

const WHOLE = [
  "\\$\\{[^{}\\s]{1,200}\\}",
  "\\$\\{\\{[^{}]{1,200}\\}\\}",
  "\\$[A-Za-z_][A-Za-z0-9_]{0,200}",
  "\\{\\{[^{}]{1,200}\\}\\}",
  "%[A-Za-z_][A-Za-z0-9_]{0,200}%",
  "<[^<>]{1,200}>",
  // The same in HTML text, as Confluence stores it: &lt;password&gt;.
  "&lt;[^&<>]{1,200}&gt;",
  "(?i)true|false|null|none|nil|undefined",
].map((source) => compile(`^(?:${source})$`));

// An ellipsis ("token=...") stands for a value left out.
const START = [
  "(?i)xxx",
  "process\\.env\\.",
  "os\\.environ",
  "import\\.meta\\.env\\.",
  "\\.\\.\\.",
  "\\x{2026}",
].map((source) => compile(`^(?:${source})`));

const ANYWHERE = compile("(?i)your[_-]|example|changeme|change[_-]me|placeholder|redacted|replace[_-]?me");

function isOneCharacterRepeated(value: string): boolean {
  const first = value.charCodeAt(0);
  for (let index = 1; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== first) {
      return false;
    }
  }
  return value.length > 1;
}

/** True for values that are documentation or template placeholders. */
export function isPlaceholder(value: string): boolean {
  if (isOneCharacterRepeated(value)) {
    return true;
  }
  if (value.search(ANYWHERE.regex) !== -1) {
    return true;
  }
  return [...WHOLE, ...START].some((pattern) => value.search(pattern.regex) !== -1);
}
