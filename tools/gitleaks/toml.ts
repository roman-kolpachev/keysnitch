// A small reader for the subset of TOML that gitleaks.toml uses: tables
// [[rules]] and [[rules.allowlists]], keys with strings ('''raw''' or
// "basic"), numbers and arrays of strings that may span lines. Anything
// else is an error, so a format change in a new gitleaks version is seen.

export interface GitleaksAllowlist {
  readonly regexes: readonly string[];
  readonly regexTarget?: string;
  readonly stopwords: readonly string[];
  readonly paths: readonly string[];
}

export interface GitleaksRule {
  readonly id: string;
  readonly description: string;
  readonly regex?: string;
  readonly path?: string;
  readonly keywords: readonly string[];
  readonly entropy?: number;
  readonly secretGroup?: number;
  readonly allowlists: readonly GitleaksAllowlist[];
}

type Value = string | number | string[];

class Reader {
  private position = 0;
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
  }

  get done(): boolean {
    return this.position >= this.text.length;
  }

  private error(message: string): Error {
    const line = this.text.slice(0, this.position).split("\n").length;
    return new Error(`gitleaks.toml line ${String(line)}: ${message}`);
  }

  skipSpaceAndComments(): void {
    for (;;) {
      const c = this.text[this.position];
      if (c === " " || c === "\t" || c === "\r" || c === "\n") {
        this.position += 1;
      } else if (c === "#") {
        const end = this.text.indexOf("\n", this.position);
        this.position = end === -1 ? this.text.length : end;
      } else {
        return;
      }
    }
  }

  readLine(): string {
    const end = this.text.indexOf("\n", this.position);
    const line = this.text.slice(this.position, end === -1 ? this.text.length : end);
    this.position = end === -1 ? this.text.length : end + 1;
    return line.trimEnd();
  }

  peekLine(): string {
    const end = this.text.indexOf("\n", this.position);
    return this.text.slice(this.position, end === -1 ? this.text.length : end).trimEnd();
  }

  readKey(): string {
    const start = this.position;
    while (/[A-Za-z0-9_]/u.test(this.text[this.position] ?? "")) {
      this.position += 1;
    }
    const key = this.text.slice(start, this.position);
    if (key === "") {
      throw this.error("expected a key");
    }
    this.skipInline();
    if (this.text[this.position] !== "=") {
      throw this.error(`expected = after ${key}`);
    }
    this.position += 1;
    this.skipInline();
    return key;
  }

  private skipInline(): void {
    while (this.text[this.position] === " " || this.text[this.position] === "\t") {
      this.position += 1;
    }
  }

  readValue(): Value {
    const c = this.text[this.position];
    if (c === "[") {
      return this.readArray();
    }
    if (c === "'" || c === '"') {
      return this.readString();
    }
    const match = /^-?\d+(?:\.\d+)?/u.exec(this.text.slice(this.position));
    if (match === null) {
      throw this.error("unknown value");
    }
    this.position += match[0].length;
    return Number(match[0]);
  }

  private readString(): string {
    if (this.text.startsWith("'''", this.position)) {
      const end = this.text.indexOf("'''", this.position + 3);
      if (end === -1) {
        throw this.error("unclosed ''' string");
      }
      const value = this.text.slice(this.position + 3, end);
      this.position = end + 3;
      return value;
    }
    if (this.text[this.position] === "'") {
      const end = this.text.indexOf("'", this.position + 1);
      if (end === -1) {
        throw this.error("unclosed ' string");
      }
      const value = this.text.slice(this.position + 1, end);
      this.position = end + 1;
      return value;
    }
    let value = "";
    this.position += 1;
    for (;;) {
      const ch = this.text[this.position];
      if (ch === undefined || ch === "\n") {
        throw this.error('unclosed " string');
      }
      this.position += 1;
      if (ch === '"') {
        return value;
      }
      if (ch === "\\") {
        const next = this.text[this.position] ?? "";
        this.position += 1;
        const escapes: Record<string, string> = { '"': '"', "\\": "\\", n: "\n", t: "\t", r: "\r" };
        const replacement = escapes[next];
        if (replacement === undefined) {
          throw this.error(`unknown escape \\${next}`);
        }
        value += replacement;
      } else {
        value += ch;
      }
    }
  }

  private readArray(): string[] {
    this.position += 1;
    const items: string[] = [];
    for (;;) {
      this.skipSpaceAndComments();
      if (this.text[this.position] === "]") {
        this.position += 1;
        return items;
      }
      const item = this.readValue();
      if (typeof item !== "string") {
        throw this.error("arrays hold strings only");
      }
      items.push(item);
      this.skipSpaceAndComments();
      if (this.text[this.position] === ",") {
        this.position += 1;
      } else if (this.text[this.position] !== "]") {
        throw this.error("expected , or ]");
      }
    }
  }
}

function asString(value: Value | undefined, key: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${key} must be a string`);
  }
  return value;
}

function asStrings(value: Value | undefined, key: string): string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  return value;
}

function asNumber(value: Value | undefined, key: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number") {
    throw new Error(`${key} must be a number`);
  }
  return value;
}

const RULE_KEYS = new Set(["id", "description", "regex", "path", "keywords", "entropy", "secretGroup"]);
const ALLOWLIST_KEYS = new Set(["description", "regexes", "regexTarget", "stopwords", "paths", "condition"]);

/** Reads every [[rules]] table. The global [allowlist] and top-level keys are skipped. */
export function parseGitleaksToml(text: string): GitleaksRule[] {
  const reader = new Reader(text);
  const rules: GitleaksRule[] = [];
  let section: "top" | "global" | "rule" | "allowlist" = "top";
  let rule: Map<string, Value> | undefined;
  let allowlists: Map<string, Value>[] = [];
  const finishRule = (): void => {
    if (rule === undefined) {
      return;
    }
    const id = asString(rule.get("id"), "id");
    if (id === undefined) {
      throw new Error("a rule without an id");
    }
    const regex = asString(rule.get("regex"), "regex");
    const path = asString(rule.get("path"), "path");
    const entropy = asNumber(rule.get("entropy"), "entropy");
    const secretGroup = asNumber(rule.get("secretGroup"), "secretGroup");
    rules.push({
      id,
      description: asString(rule.get("description"), "description") ?? "",
      ...(regex === undefined ? {} : { regex }),
      ...(path === undefined ? {} : { path }),
      keywords: asStrings(rule.get("keywords"), "keywords"),
      ...(entropy === undefined ? {} : { entropy }),
      ...(secretGroup === undefined ? {} : { secretGroup }),
      allowlists: allowlists.map((list) => {
        const regexTarget = asString(list.get("regexTarget"), "regexTarget");
        return {
          regexes: asStrings(list.get("regexes"), "regexes"),
          ...(regexTarget === undefined ? {} : { regexTarget }),
          stopwords: asStrings(list.get("stopwords"), "stopwords"),
          paths: asStrings(list.get("paths"), "paths"),
        };
      }),
    });
    rule = undefined;
    allowlists = [];
  };
  for (;;) {
    reader.skipSpaceAndComments();
    if (reader.done) {
      break;
    }
    const line = reader.peekLine();
    if (line.startsWith("[")) {
      reader.readLine();
      if (line === "[[rules]]") {
        finishRule();
        rule = new Map();
        section = "rule";
      } else if (line === "[[rules.allowlists]]") {
        if (rule === undefined) {
          throw new Error("an allowlist outside a rule");
        }
        allowlists.push(new Map());
        section = "allowlist";
      } else if (line === "[allowlist]" || line === "[[allowlists]]") {
        finishRule();
        section = "global";
      } else {
        throw new Error(`unknown table ${line}`);
      }
      continue;
    }
    const key = reader.readKey();
    const value = reader.readValue();
    if (section === "rule" && rule !== undefined) {
      if (!RULE_KEYS.has(key)) {
        throw new Error(`unknown rule key ${key}`);
      }
      rule.set(key, value);
    } else if (section === "allowlist") {
      if (!ALLOWLIST_KEYS.has(key)) {
        throw new Error(`unknown allowlist key ${key}`);
      }
      allowlists.at(-1)?.set(key, value);
    }
  }
  finishRule();
  return rules;
}
