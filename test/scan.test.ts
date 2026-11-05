// Scenarios: scan() finds credentials in any text with a given list of
// rules. Edge cases are the point of this file.
// - a finding is the secret's own range (its group), with the rule's id,
//   vendor, label and severity; the value itself is never in a finding;
// - keywords gate a rule: no keyword in the text, the rule does not run;
//   keywords are found in any case;
// - minEntropy, allow patterns, a rule's validate and the caller's ignore
//   drop a match; the global placeholder filter drops obvious examples;
// - overlapping findings become one finding that covers all of them, so
//   nothing is left readable; the widest rule wins, and on a tie the
//   specific rule wins over a generic one;
// - findings come back sorted by start, without duplicates;
// - maxFindings stops the scan and says it is not complete;
// - custom matchers add findings, and a broken one is refused clearly;
// - odd input: empty text, one character, line endings, Unicode spaces,
//   zero-width characters, emoji before a key (UTF-16 offsets), null
//   bytes, very long text;
// - the same input always gives the same output, in any rule order, and
//   nothing is kept between calls.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defineRule } from "../src/rule.ts";
import { scan, secretRange, type Finding } from "../src/scan.ts";

const body = "q7Lm2Xp9Rt4Vz8Kc"; // 16 mixed characters, built here, not a real key
const demo = defineRule({
  id: "demo-token",
  vendor: "Demo",
  label: "Demo token",
  severity: "high",
  keywords: ["dmo_"],
  pattern: "dmo_[A-Za-z0-9]{16}(?![A-Za-z0-9])",
});
const assigned = defineRule({
  id: "demo-assignment",
  vendor: "Generic",
  label: "Secret in a setting",
  severity: "medium",
  keywords: ["secret"],
  pattern: "(?i)secret[ \\t]{0,3}=[ \\t]{0,3}([^\\s\"']{8,200})",
  generic: true,
});

const values = (text: string, findings: readonly Finding[]): string[] =>
  findings.map((finding) => text.slice(finding.start, finding.end));

function find(text: string, rules = [demo]): string[] {
  return values(text, scan(text, { rules }).findings);
}

describe("basic findings", () => {
  it("returns the range and the rule's facts, not the value", () => {
    const text = `token: dmo_${body} end`;
    const result = scan(text, { rules: [demo] });
    assert.equal(result.complete, true);
    assert.deepEqual(result.findings, [
      { ruleId: "demo-token", vendor: "Demo", label: "Demo token", severity: "high", start: 7, end: 27 },
    ]);
    assert.ok(!JSON.stringify(result).includes(body));
  });

  it("returns only the secret group of a rule", () => {
    assert.deepEqual(find(`secret = ${body}x`, [assigned]), [`${body}x`]);
  });

  it("finds keys at the very start and the very end of the text", () => {
    assert.deepEqual(find(`dmo_${body}`), [`dmo_${body}`]);
    assert.deepEqual(find(`x dmo_${body}`), [`dmo_${body}`]);
    assert.deepEqual(find(`dmo_${body} x`), [`dmo_${body}`]);
  });

  it("finds a key wrapped in quotes, brackets, backticks and markdown", () => {
    for (const [open, close] of [
      ['"', '"'],
      ["'", "'"],
      ["(", ")"],
      ["[", "]"],
      ["{", "}"],
      ["<", ">"],
      ["`", "`"],
      ["```\n", "\n```"],
      ["**", "**"],
    ] as const) {
      assert.deepEqual(find(`${open}dmo_${body}${close}`), [`dmo_${body}`], open);
    }
  });

  it("finds a key in JSON, YAML, .env and a URL query", () => {
    assert.deepEqual(find(`{"token":"dmo_${body}"}`), [`dmo_${body}`]);
    assert.deepEqual(find(`token: dmo_${body}\n`), [`dmo_${body}`]);
    assert.deepEqual(find(`TOKEN=dmo_${body}\r\n`), [`dmo_${body}`]);
    assert.deepEqual(find(`https://x.test/?t=dmo_${body}&a=1`), [`dmo_${body}`]);
  });

  it("finds a key after any line ending and Unicode space", () => {
    for (const separator of ["\n", "\r", "\r\n", "\t", "\u00a0", "\u2028", "\u3000", "\ufeff"]) {
      assert.deepEqual(
        find(`a${separator}dmo_${body}${separator}b`),
        [`dmo_${body}`],
        JSON.stringify(separator),
      );
    }
  });

  it("does not find a key glued to more key characters", () => {
    assert.deepEqual(find(`dmo_${body}x`), []);
  });

  it("finds two keys that touch only through one separator", () => {
    assert.deepEqual(find(`dmo_${body},dmo_${body.toLowerCase()}`), [
      `dmo_${body}`,
      `dmo_${body.toLowerCase()}`,
    ]);
  });

  it("keeps UTF-16 offsets right after emoji and astral characters", () => {
    const text = `\ud83d\ude00\ud83d\udd11 \ud835\udcb3 dmo_${body}`;
    const [finding] = scan(text, { rules: [demo] }).findings;
    assert.ok(finding !== undefined);
    assert.equal(text.slice(finding.start, finding.end), `dmo_${body}`);
  });

  it("does not see a key broken by a zero-width character", () => {
    assert.deepEqual(find(`dmo_${body.slice(0, 8)}\u200b${body.slice(8)}`), []);
  });

  it("does not see look-alike prefixes", () => {
    // Cyrillic "\u043e" and full-width letters are not "o" and "dmo_".
    assert.deepEqual(find(`dm\u043e_${body}`), []);
    assert.deepEqual(find(`\uff44\uff4d\uff4f_${body}`), []);
  });

  it("handles null bytes around a key", () => {
    assert.deepEqual(find(`\u0000dmo_${body}\u0000`), [`dmo_${body}`]);
  });
});

describe("rules and groups", () => {
  it("refuses a rule that was not made by defineRule", () => {
    assert.throws(() => scan(`dmo_${body}`, { rules: [{ ...demo }] }), TypeError);
  });

  it("skips a match whose secret group did not take part", () => {
    const rule = defineRule({
      ...demo,
      id: "either",
      pattern: "(?:key=([a-z0-9]{8})|dmo_[A-Za-z0-9]{16})",
      secretGroup: 1,
    });
    assert.deepEqual(find(`dmo_${body} key=abcd1234`, [rule]), ["abcd1234"]);
  });

  it("takes the first group that took part when the rule does not name one", () => {
    const rule = defineRule({
      id: "two-shapes",
      vendor: "Demo",
      label: "Demo",
      severity: "high",
      keywords: [],
      pattern: "(?:key=([a-z0-9]{8})|tok=([A-Z]{8}))",
    });
    assert.deepEqual(find("key=abcd1234 tok=ABCDEFGH", [rule]), ["abcd1234", "ABCDEFGH"]);
  });

  it("finds no range in a match made without indices", () => {
    const match = /a(b)/u.exec("ab");
    assert.ok(match !== null);
    assert.equal(secretRange(match, 1), undefined);
    assert.equal(secretRange(match, "first"), undefined);
  });

  it("takes the whole match when no group took part", () => {
    const rule = defineRule({
      id: "group-or-not",
      vendor: "Demo",
      label: "Demo",
      severity: "high",
      keywords: [],
      pattern: "(?:key=([a-z0-9]{8})|tok_[A-Z]{8})",
    });
    assert.deepEqual(find("tok_ABCDEFGH", [rule]), ["tok_ABCDEFGH"]);
  });

  it("skips a match whose secret group is empty", () => {
    const rule = defineRule({
      ...demo,
      id: "maybe",
      keywords: [],
      pattern: "x([a-z]{0,4})y",
      secretGroup: 1,
    });
    assert.deepEqual(find("xy xaby", [rule]), ["ab"]);
  });

  it("runs the built-in rules when no rules are given", () => {
    assert.deepEqual(scan("plain text with nothing secret"), { findings: [], complete: true });
  });
});

describe("empty and tiny input", () => {
  it("returns nothing for empty text, white space and one character", () => {
    for (const text of ["", " ", "\n", "d", "dmo_"]) {
      assert.deepEqual(scan(text, { rules: [demo] }), { findings: [], complete: true });
    }
  });

  it("refuses a value that is not a string, without echoing it", () => {
    assert.throws(
      () => Reflect.apply(scan, undefined, [Symbol("secret-value")]),
      (error: unknown) => error instanceof TypeError && !error.message.includes("secret-value"),
    );
  });
});

describe("keywords", () => {
  it("skips a rule when none of its keywords is in the text", () => {
    let called = false;
    const rule = defineRule({ ...demo, keywords: ["other"], validate: () => (called = true) });
    assert.deepEqual(scan(`dmo_${body}`, { rules: [rule] }).findings, []);
    assert.equal(called, false);
  });

  it("finds keywords in any case", () => {
    const rule = defineRule({ ...demo, id: "upper", pattern: "(?i)dmo_[A-Za-z0-9]{16}" });
    assert.deepEqual(find(`DMO_${body}`, [rule]), [`DMO_${body}`]);
  });

  it("always runs a rule without keywords", () => {
    const rule = defineRule({ ...demo, keywords: [] });
    assert.deepEqual(find(`dmo_${body}`, [rule]), [`dmo_${body}`]);
  });
});

describe("filters", () => {
  it("drops a secret below the rule's minimum entropy", () => {
    const rule = defineRule({ ...demo, minEntropy: 3.5 });
    assert.deepEqual(find(`dmo_${"a".repeat(16)}`, [rule]), []);
    assert.deepEqual(find(`dmo_${body}`, [rule]), [`dmo_${body}`]);
  });

  it("drops a secret that matches an allow pattern of the rule", () => {
    const rule = defineRule({ ...demo, allow: ["dmo_0{16}"] });
    assert.deepEqual(find(`dmo_${"0".repeat(16)}`, [rule]), []);
  });

  it("an allow pattern skips a secret that contains its match, like gitleaks", () => {
    const rule = defineRule({ ...demo, allow: ["0{4}"] });
    assert.deepEqual(find(`dmo_0000${body.slice(4)}`, [rule]), []);
    assert.deepEqual(find(`dmo_${body}`, [rule]), [`dmo_${body}`]);
  });

  it("an anchored allow pattern must match the whole secret", () => {
    const rule = defineRule({ ...demo, allow: ["^dmo_0{4}$"] });
    assert.deepEqual(find(`dmo_0000${body.slice(4)}`, [rule]), [`dmo_0000${body.slice(4)}`]);
  });

  it("drops a secret its validate function refuses", () => {
    const rule = defineRule({ ...demo, validate: (secret) => secret.endsWith("c") });
    assert.deepEqual(find(`dmo_${body}`, [rule]), [`dmo_${body}`]);
    assert.deepEqual(find(`dmo_${body.slice(0, 15)}d`, [rule]), []);
  });

  it("drops a secret the caller ignores, and gives the caller the value and finding", () => {
    const seen: string[] = [];
    const result = scan(`dmo_${body} dmo_${body.toUpperCase()}`, {
      rules: [demo],
      ignore: (value, finding) => {
        seen.push(`${finding.ruleId}:${value}`);
        return value === `dmo_${body}`;
      },
    });
    assert.equal(result.findings.length, 1);
    assert.deepEqual(seen, [`demo-token:dmo_${body}`, `demo-token:dmo_${body.toUpperCase()}`]);
  });

  it("drops documentation placeholders for every rule", () => {
    const loose = defineRule({ ...assigned, id: "loose" });
    for (const value of [
      "${SECRET_VALUE}",
      "${{ secrets.MY_SECRET }}",
      "$SECRET_VALUE",
      "{{secret_value}}",
      "%SECRET_VALUE%",
      "<your-secret-here>",
      "your_secret_value",
      "xxxxxxxxxxxx",
      "XXXXXXXXXXXXXXXX",
      "************",
      "............",
      "changeme123",
      "my-example-secret",
      "placeholder",
      "process.env.SECRET",
      "os.environ[SECRET]",
      "REDACTED_VALUE",
    ]) {
      assert.deepEqual(find(`secret = ${value}`, [loose]), [], value);
    }
  });

  it("keeps a real-looking value next to placeholder words", () => {
    assert.deepEqual(find(`secret = ${body}`, [assigned]), [body]);
  });
});

describe("overlaps", () => {
  const wide = defineRule({
    id: "wide",
    vendor: "Generic",
    label: "Setting",
    severity: "medium",
    keywords: ["token"],
    pattern: "token=([^\\s]{8,200})",
    generic: true,
  });

  it("keeps the specific rule when both cover the same text", () => {
    const text = `token=dmo_${body}`;
    const findings = scan(text, { rules: [wide, demo] }).findings;
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, "demo-token");
    assert.deepEqual(scan(text, { rules: [demo, wide] }).findings, findings);
    assert.deepEqual(values(text, findings), [`dmo_${body}`]);
  });

  it("keeps the wider range when a generic match is longer, so nothing stays readable", () => {
    const text = `token=dmo_${body}/x`;
    const findings = scan(text, { rules: [demo, wide] }).findings;
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, "wide");
    assert.deepEqual(values(text, findings), [`dmo_${body}/x`]);
  });

  it("joins partly overlapping findings into one range", () => {
    const left = defineRule({ ...demo, id: "left", keywords: [], pattern: "aaa[0-9]{3}" });
    const right = defineRule({ ...demo, id: "right", keywords: [], pattern: "[0-9]{3}bbbb" });
    const text = "xaaa123bbbbx";
    const findings = scan(text, { rules: [left, right] }).findings;
    assert.deepEqual(values(text, findings), ["aaa123bbbb"]);
    assert.equal(findings[0]?.ruleId, "right");
  });

  it("keeps findings that only touch as separate findings", () => {
    const left = defineRule({ ...demo, id: "left", keywords: [], pattern: "aaa[0-9]{3}" });
    const right = defineRule({ ...demo, id: "right", keywords: [], pattern: "bbb[0-9]{3}" });
    const text = "aaa123bbb456";
    assert.deepEqual(values(text, scan(text, { rules: [left, right] }).findings), ["aaa123", "bbb456"]);
  });

  it("does not report the same key twice, and names it the same way in any order", () => {
    const copy = defineRule({ ...demo, id: "copy" });
    const text = `dmo_${body}`;
    const one = scan(text, { rules: [demo, copy, demo] }).findings;
    const two = scan(text, { rules: [copy, demo] }).findings;
    assert.equal(one.length, 1);
    assert.equal(one[0]?.ruleId, "copy");
    assert.deepEqual(one, two);
  });

  it("gives the same result for any order of rules", () => {
    const text = `token=dmo_${body}/x and dmo_${body} and secret=${body}`;
    const one = scan(text, { rules: [demo, wide, assigned] });
    const two = scan(text, { rules: [assigned, wide, demo] });
    assert.deepEqual(one, two);
  });

  it("returns findings sorted by start", () => {
    const text = `secret=${body} dmo_${body}`;
    const findings = scan(text, { rules: [demo, assigned] }).findings;
    assert.deepEqual(
      findings.map((finding) => finding.start),
      [...findings.map((finding) => finding.start)].sort((a, b) => a - b),
    );
    assert.equal(findings.length, 2);
  });
});

describe("limits", () => {
  it("stops at maxFindings and says the scan is not complete", () => {
    const text = Array.from({ length: 5 }, (_, i) => `dmo_${body.slice(0, 15)}${String(i)}`).join(" ");
    const result = scan(text, { rules: [demo], maxFindings: 3 });
    assert.equal(result.findings.length, 3);
    assert.equal(result.complete, false);
    const exact = scan(text, { rules: [demo], maxFindings: 5 });
    assert.equal(exact.findings.length, 5);
    assert.equal(exact.complete, true);
  });

  it("refuses a maxFindings that is not a positive whole number", () => {
    for (const maxFindings of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => scan("x", { rules: [demo], maxFindings }), RangeError);
    }
  });

  it("finds a key at the end of a 5 MB text quickly", () => {
    const text = `${"lorem ipsum dmo_ ".repeat(300_000)}dmo_${body}`;
    const started = performance.now();
    const result = scan(text, { rules: [demo, assigned] });
    const elapsed = performance.now() - started;
    assert.deepEqual(values(text, result.findings), [`dmo_${body}`]);
    assert.ok(elapsed < 2000, `took ${String(elapsed)} ms`);
  });

  it("finds the same key many times", () => {
    const text = `dmo_${body} `.repeat(200);
    assert.equal(scan(text, { rules: [demo] }).findings.length, 200);
  });
});

describe("custom matchers", () => {
  const matcher = {
    id: "custom-thing",
    vendor: "Acme",
    label: "Acme secret",
    severity: "low",
    find: (text: string) => {
      const at = text.indexOf("acme:");
      return at === -1 ? [] : [{ start: at, end: at + 9 }];
    },
  } as const;

  it("adds the findings of a custom matcher", () => {
    const text = "x acme:1234 y";
    const result = scan(text, { rules: [], matchers: [matcher] });
    assert.deepEqual(values(text, result.findings), ["acme:1234"]);
    assert.equal(result.findings[0]?.ruleId, "custom-thing");
  });

  it("refuses a custom matcher that returns a bad range, without the text", () => {
    for (const range of [
      { start: -1, end: 2 },
      { start: 2, end: 2 },
      { start: 3, end: 2 },
      { start: 0, end: 999 },
      { start: 0.5, end: 2 },
    ]) {
      const broken = { ...matcher, find: () => [range] };
      assert.throws(
        () => scan("acme:1234", { rules: [], matchers: [broken] }),
        (error: unknown) =>
          error instanceof RangeError &&
          error.message.includes("custom-thing") &&
          !error.message.includes("acme:1234"),
      );
    }
  });

  it("runs custom matchers through ignore and the placeholder filter", () => {
    assert.deepEqual(
      scan("x acme:1234", { rules: [], matchers: [matcher], ignore: () => true }).findings,
      [],
    );
  });
});

describe("no state between calls", () => {
  it("gives the same answer twice and for interleaved texts", () => {
    const one = `dmo_${body}`;
    const two = `a dmo_${body.toLowerCase()} b`;
    assert.deepEqual(scan(one, { rules: [demo] }), scan(one, { rules: [demo] }));
    const first = scan(one, { rules: [demo] });
    scan(two, { rules: [demo] });
    assert.deepEqual(scan(one, { rules: [demo] }), first);
  });
});
