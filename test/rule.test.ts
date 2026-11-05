// Scenarios: defineRule() is how every rule, built in or added by a user,
// enters keysnitch. It checks the rule once, up front:
// - the pattern must pass the safety check (an unsafe one is refused);
// - the id is kebab-case, vendor and label are not empty, keywords are
//   lower case and not empty strings, severity is one of three values;
// - the secret group must exist in the pattern;
// - minEntropy must be a number between 0 and 8;
// - allow patterns are checked like any other pattern;
// - the result is frozen, so a caller cannot change a rule later.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defineRule, RuleError } from "../src/rule.ts";
import { UnsafePatternError } from "../src/pattern/compile.ts";

const base = {
  id: "demo-token",
  vendor: "Demo",
  label: "Demo token",
  severity: "high",
  keywords: ["dmo_"],
  pattern: "dmo_[a-z0-9]{8}",
} as const;

describe("defineRule", () => {
  it("accepts a valid rule and freezes it", () => {
    const rule = defineRule(base);
    assert.equal(rule.id, "demo-token");
    assert.ok(Object.isFrozen(rule));
    assert.ok(Object.isFrozen(rule.keywords));
    assert.equal(rule.secretGroup, 0);
  });

  it("uses the first group as the secret when the pattern has one", () => {
    assert.equal(defineRule({ ...base, pattern: "key=(dmo_[a-z0-9]{8})" }).secretGroup, 1);
    assert.equal(defineRule({ ...base, pattern: "(k)ey=(dmo_[a-z0-9]{8})", secretGroup: 2 }).secretGroup, 2);
  });

  it("refuses a secret group the pattern does not have", () => {
    assert.throws(() => defineRule({ ...base, secretGroup: 1 }), RuleError);
    assert.throws(() => defineRule({ ...base, pattern: "(dmo_[a-z0-9]{8})", secretGroup: 2 }), RuleError);
    assert.throws(() => defineRule({ ...base, secretGroup: -1 }), RuleError);
    assert.throws(() => defineRule({ ...base, secretGroup: 0.5 }), RuleError);
  });

  it("refuses an unsafe pattern", () => {
    assert.throws(() => defineRule({ ...base, pattern: "dmo_[a-z0-9]+" }), UnsafePatternError);
  });

  it("refuses bad metadata", () => {
    const bad = [
      { ...base, id: "Demo Token" },
      { ...base, id: "" },
      { ...base, id: "-demo" },
      { ...base, vendor: " " },
      { ...base, label: "" },
      { ...base, keywords: ["DMO_"] },
      { ...base, keywords: [""] },
      { ...base, severity: "critical" },
      { ...base, minEntropy: 9 },
      { ...base, minEntropy: -1 },
      { ...base, minEntropy: Number.NaN },
      { ...base, aliases: [""] },
    ];
    for (const spec of bad) {
      // Reflect.apply stands in for a JavaScript caller without types.
      assert.throws(() => Reflect.apply(defineRule, undefined, [spec]), RuleError, JSON.stringify(spec));
    }
  });

  it("checks allow patterns like rule patterns", () => {
    assert.throws(() => defineRule({ ...base, allow: ["x+"] }), UnsafePatternError);
    const rule = defineRule({ ...base, allow: ["dmo_0{8}"] });
    assert.equal(rule.allow.length, 1);
  });

  it("keeps optional fields", () => {
    const rule = defineRule({
      ...base,
      aliases: ["Example"],
      rotate: "Demo console, Tokens: revoke.",
      minEntropy: 3,
      generic: true,
      source: "test",
    });
    assert.deepEqual(rule.aliases, ["Example"]);
    assert.equal(rule.rotate, "Demo console, Tokens: revoke.");
    assert.equal(rule.minEntropy, 3);
    assert.equal(rule.generic, true);
    assert.equal(rule.source, "test");
  });

  it("defaults optional fields", () => {
    const rule = defineRule(base);
    assert.deepEqual(rule.aliases, []);
    assert.deepEqual(rule.allow, []);
    assert.equal(rule.generic, false);
    assert.equal(rule.minEntropy, 0);
    assert.equal(rule.rotate, undefined);
  });
});
