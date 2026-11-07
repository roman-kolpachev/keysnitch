// Scenarios: keysnitch covers at least everything gitleaks covers.
// - every rule id in the vendored gitleaks config is a built-in keysnitch
//   rule (the contract tests prove each one finds its own example), or it
//   is skipped with a written reason and, where it matters, a keysnitch
//   rule that takes its place;
// - src/rules/gitleaks.ts is exactly what the importer makes from the
//   vendored config, so nobody edits generated rules by hand;
// - the version in the generated file is the vendored version.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rules } from "#src/rules/index.ts";
import { defineRule } from "#src/rule.ts";
import { scan } from "#src/scan.ts";
import { GITLEAKS_VERSION, gitleaksRules, gitleaksSkipped } from "#src/rules/gitleaks.ts";
import { buildGitleaksRules } from "../../tools/gitleaks/build.ts";

const build = buildGitleaksRules();
const builtIn = new Set(rules.map((rule) => rule.id));

/** A skipped gitleaks rule and the keysnitch rules that cover its ground instead (none: nothing to cover in text). */
const REPLACED_BY: Readonly<Record<string, readonly string[]>> = {
  "generic-api-key": ["generic-secret-assignment", "generic-secret-colon", "generic-env-secret"],
  "pkcs12-file": [],
};

describe("the gitleaks floor", () => {
  it("knows all 222 rules of the vendored config", () => {
    assert.equal(build.ids.length, 222);
  });

  it("has every gitleaks rule as a built-in rule, or skips it with a reason and a replacement", () => {
    const skipped = new Map(gitleaksSkipped.map((entry) => [entry.id, entry.reason]));
    const missing = build.ids.filter((id) => !builtIn.has(id) && !skipped.has(id));
    assert.deepEqual(missing, []);
    for (const [id, reason] of skipped) {
      assert.ok(reason.length > 20, `${id} needs a real reason`);
      const replacements = REPLACED_BY[id];
      assert.ok(replacements !== undefined, `${id} is skipped without a decision about its replacement`);
      for (const replacement of replacements) {
        assert.ok(builtIn.has(replacement), `${id} should be covered by ${replacement}`);
      }
    }
  });

  it("has a generated file that matches the importer", () => {
    assert.deepEqual(build.failures, []);
    assert.equal(GITLEAKS_VERSION, build.version);
    assert.deepEqual(gitleaksRules, build.specs);
    assert.deepEqual(gitleaksSkipped, build.skipped);
  });
});

// Scenario: gitleaks allows some public sample keys by listing them whole
// (Google API keys from documentation). keysnitch keeps them allowed, but
// no rule file and no built file may hold a value that any scanner, GitHub's
// secret scanning included, reports as a leaked key.
describe("allow lists", () => {
  it("hold no value that a built-in rule would report, once the allow lists are left out", () => {
    const bare = rules.map((rule) => defineRule({ ...rule, allow: [] }));
    const keyShaped = rules.flatMap((rule) =>
      rule.allow
        .filter((entry) => scan(entry, { rules: bare }).findings.length > 0)
        .map((entry) => `${rule.id}: ${entry.slice(0, 8)}...`),
    );
    assert.deepEqual(keyShaped, []);
  });

  it("still keep a documented sample key from being reported", () => {
    const gcp = rules.find((rule) => rule.id === "gcp-api-key");
    assert.ok(gcp !== undefined && gcp.allow.length > 0);
    // The first allowed sample, written out from its pattern, is not reported.
    const sample =
      gcp.allow[0]?.replace(/\\x\{([0-9a-f]{2})\}/gu, (_, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      ) ?? "";
    assert.ok(sample.length >= 39);
    assert.deepEqual(
      scan(`key = "${sample}"`).findings.filter((f) => f.ruleId === "gcp-api-key"),
      [],
    );
  });
});
