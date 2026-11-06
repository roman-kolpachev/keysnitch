// Scenarios: keysnitch finds everything the free checker on
// simplify-software.org (/tools/api-key-leak-checker) finds. Its 47 formats
// are in test/fixtures/website-formats.json (patterns only).
// - for every format, examples are built from the checker's own pattern at
//   test time; keysnitch must cover the whole value the checker reports;
// - for formats where the checker reports a setting with its name
//   (password=..., a database URL), keysnitch must cover the value part;
// - the private key format is tested with a whole key block, because a
//   header alone is not a secret;
// - one format is not a secret by itself and is listed with the reason.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parse } from "#src/pattern/parse.ts";
import { scan } from "#src/scan.ts";
import { boundRepeats } from "../../tools/gitleaks/convert.ts";
import { random, sample } from "../support/sample.ts";

interface Format {
  readonly id: string;
  readonly name: string;
  readonly source: string;
  readonly flags: string;
}

function isFormat(value: unknown): value is Format {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  return ["id", "name", "source", "flags"].every((key) => typeof Reflect.get(value, key) === "string");
}

const parsed: unknown = JSON.parse(
  readFileSync(new URL("../fixtures/website-formats.json", import.meta.url), "utf8"),
);
const formats: readonly Format[] = Array.isArray(parsed) ? parsed.filter(isFormat) : [];

/** Formats that are not a credential on their own. */
const NOT_A_SECRET: Readonly<Record<string, string>> = {
  "gcp-service-account":
    'the checker flags the "type": "service_account" marker; the secret in that file is its private key, which the private-key rule finds',
};

/** Formats whose match holds a name or a host around the secret: only the value must be covered. */
const VALUE_AFTER: Readonly<Record<string, RegExp>> = {
  "password-assignment": /[:=]\s*["']?/u,
  "connection-string": /:\/\/[^\s:/@]+:/u,
  "url-credentials": /:\/\/[^\s:/@]+:/u,
  "azure-storage-key": /AccountKey=/u,
};

/**
 * Where the checker's pattern accepts text no real credential has, examples
 * must also match the real shape. Sentry: the checker's sntr[yu]s_ accepts
 * "sntrus_", which no Sentry token starts with (and it misses user tokens,
 * which start with sntryu_; keysnitch finds those).
 */
const CHECKER_TOO_WIDE: Readonly<Record<string, RegExp>> = {
  "sentry-token": /^sntrys_/u,
};

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function examples(format: Format): string[] {
  if (format.id === "private-key") {
    const next = random(5);
    const body = Array.from({ length: 6 }, () =>
      Array.from({ length: 64 }, () => BASE64.charAt(Math.floor(next() * 64))).join(""),
    ).join("\n");
    return [`-----BEGIN RSA PRIVATE KEY-----\nMII${body}\n-----END RSA PRIVATE KEY-----`];
  }
  const tree = parse(`${format.flags.includes("i") ? "(?i)" : ""}${boundRepeats(format.source, 160)}`);
  const checker = new RegExp(format.source, format.flags.replace("g", ""));
  const real = CHECKER_TOO_WIDE[format.id];
  const out: string[] = [];
  for (let seed = 1; out.length < 5 && seed < 500; seed += 1) {
    const made = sample(tree, random(seed));
    if (checker.exec(made)?.[0] === made && (real === undefined || real.test(made))) {
      out.push(made);
    }
  }
  return out;
}

describe("parity with the website checker", () => {
  it("has all 47 formats of the checker", () => {
    assert.equal(formats.length, 47);
  });

  for (const format of formats) {
    it(`${format.id} (${format.name})`, (context) => {
      const reason = NOT_A_SECRET[format.id];
      if (reason !== undefined) {
        context.diagnostic(`not a secret by itself: ${reason}`);
        return;
      }
      const list = examples(format);
      assert.ok(list.length > 0, "no example could be built from the checker's pattern");
      for (const example of list) {
        const text = `note: ${example}\n`;
        const start = text.indexOf(example);
        const prefix = VALUE_AFTER[format.id]?.exec(example);
        const valueStart =
          start + (prefix === undefined || prefix === null ? 0 : prefix.index + prefix[0].length);
        const valueEnd = start + example.length;
        const findings = scan(text).findings;
        const covered =
          findings.some((finding) => finding.start <= valueStart && finding.end >= valueEnd) ||
          (prefix !== undefined &&
            findings.some((finding) => finding.start <= valueStart && finding.end > valueStart));
        assert.ok(
          covered,
          `not covered: ${JSON.stringify(example.slice(0, 50))} -> ${JSON.stringify(findings.map((f) => f.ruleId))}`,
        );
      }
    });
  }
});
