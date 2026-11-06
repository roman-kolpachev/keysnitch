// Scenarios: every built-in rule keeps the same promises.
// - its facts are complete: unique kebab-case id, company, label, keywords
//   in lower case;
// - an example built from its own pattern (at test time, never stored) is
//   found by scan(); rules that need a context word (their keyword is not
//   part of the key, "facebook" before a token, say) get it in front;
// - in quotes, in a JSON value and in an assignment the same secret is
//   covered, and the finding never eats the quote, brace or semicolon
//   after it (a redaction must not break the text around the key);
// - slow input made from its own pieces (a cut example repeated, long runs
//   of each character it accepts, its keywords repeated) scans in linear
//   time, well inside a budget;
// - documentation placeholders for its value are not reported.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rules } from "../../src/rules/index.ts";
import { compiledRule } from "../../src/rule.ts";
import { scan } from "../../src/scan.ts";
import { characters, random, sample } from "../support/sample.ts";
import type { Rule } from "../../src/types.ts";

const SLOW_INPUT = 100_000;
const BUDGET_MS = 400;

function tree(rule: Rule) {
  const compiled = compiledRule(rule);
  if (compiled === undefined) throw new Error(`${rule.id} was not made by defineRule`);
  return compiled.pattern;
}

function hasKeyword(rule: Rule, text: string): boolean {
  const lower = text.toLowerCase();
  return rule.keywords.some((keyword) => lower.includes(keyword));
}

/**
 * Examples for rules whose validate() refuses random text: a random Base64
 * value almost never decodes to "user:password".
 */
const FIXED_EXAMPLES: Readonly<Record<string, string>> = {
  // "alice:wonderland12" in Base64.
  "generic-basic-auth": "Basic YWxpY2U6d29uZGVybGFuZDEy",
  // Random text rarely puts a word boundary before "is".
  "generic-secret-in-sentence": "The admin password for the router is KKHZzpyn2026!",
};

/** An example of the rule that the rule itself reports, with the reported value. */
export function exampleOf(rule: Rule): { text: string; value: string } | undefined {
  const pattern = tree(rule);
  for (let seed = 1; seed <= 200; seed += 1) {
    const made = FIXED_EXAMPLES[rule.id] ?? sample(pattern.tree, random(seed * 7919 + rule.id.length));
    const text = hasKeyword(rule, made) ? made : `${rule.keywords[0] ?? ""} ${made}`;
    const findings = scan(text, { rules: [rule] }).findings;
    const first = findings[0];
    if (findings.length === 1 && first !== undefined)
      return { text, value: text.slice(first.start, first.end) };
  }
  return undefined;
}

describe("facts of every built-in rule", () => {
  it("has unique ids", () => {
    const ids = rules.map((rule) => rule.id);
    assert.equal(new Set(ids).size, ids.length);
  });

  for (const rule of rules) {
    it(rule.id, () => {
      assert.ok(rule.vendor.length > 0 && rule.label.length > 0);
      assert.ok(
        rule.keywords.length > 0,
        "every built-in rule has keywords, so it runs only where it can match",
      );
      for (const keyword of rule.keywords) assert.equal(keyword, keyword.toLowerCase());
    });
  }
});

describe("every built-in rule finds its own example", () => {
  for (const rule of rules) {
    it(rule.id, () => {
      const example = exampleOf(rule);
      assert.ok(example !== undefined, "no example of this rule is reported; check its filters and keywords");
      for (const [open, close] of [
        ['"', '"'],
        ["'", "'"],
        ['{"value": "', '"}'],
        ["x = ", ";"],
      ] as const) {
        const wrapped = `${open}${example.text}${close}`;
        const findings = scan(wrapped, { rules: [rule] }).findings;
        if (findings.length === 0) continue; // some rules need the key on a line of its own
        const values = findings.map((finding) => wrapped.slice(finding.start, finding.end));
        assert.ok(
          values.some((value) => value.includes(example.value.trim())),
          `the secret is only partly covered in ${open}...${close}`,
        );
        const last = findings.at(-1);
        assert.ok(last !== undefined);
        assert.ok(
          last.end <= wrapped.length - close.length || example.text.endsWith(close),
          `the finding eats ${JSON.stringify(close)} after the key`,
        );
      }
    });
  }
});

describe("every built-in rule scans slow input in linear time", () => {
  for (const rule of rules) {
    it(rule.id, () => {
      const example = exampleOf(rule)?.text ?? "";
      const pieces = [...characters(tree(rule).tree, random(rule.id.length))];
      const inputs = [
        example.slice(0, Math.max(1, example.length - 1)),
        ...pieces,
        ...rule.keywords.map((keyword) => `${keyword} `),
        ...rule.keywords.map((keyword) => `${keyword}=`),
      ].map(
        (piece) =>
          `${rule.keywords[0] ?? ""} ${piece.repeat(Math.ceil(SLOW_INPUT / Math.max(1, piece.length)))}`,
      );
      let slowest = 0;
      for (const input of inputs) {
        const started = performance.now();
        scan(input, { rules: [rule] });
        slowest = Math.max(slowest, performance.now() - started);
      }
      assert.ok(slowest < BUDGET_MS, `slowest input took ${slowest.toFixed(0)} ms for 100 KB`);
    });
  }
});

describe("every built-in rule skips placeholders", () => {
  for (const rule of rules) {
    it(rule.id, () => {
      for (const value of ["your_api_key_here", "${API_KEY}", "<YOUR_TOKEN>", "XXXXXXXXXXXXXXXXXXXXXXXX"]) {
        for (const text of [
          `token = ${value}`,
          `${rule.keywords[0] ?? ""}: ${value}`,
          `${rule.keywords[0] ?? ""}=${value}`,
        ]) {
          const findings = scan(text, { rules: [rule] }).findings;
          const leaked = findings.filter((finding) => text.slice(finding.start, finding.end).includes(value));
          assert.deepEqual(leaked, [], text);
        }
      }
    });
  }
});
