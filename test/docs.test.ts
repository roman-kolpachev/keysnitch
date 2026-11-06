// Scenarios: the documents say what the code does.
// - docs/rules.md lists exactly the built-in rules (it is generated);
// - the README states the number of rules and the gitleaks version that
//   the code has;
// - CHANGELOG.md has an Unreleased section on top.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { rulesDoc } from "../tools/rules-doc.ts";
import { rules } from "#src/rules/index.ts";
import { GITLEAKS_VERSION } from "#src/rules/gitleaks.ts";

const read = (path: string): string => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

describe("documents", () => {
  it("has an up-to-date docs/rules.md (run node tools/rules-doc.ts)", () => {
    assert.equal(read("docs/rules.md"), rulesDoc());
  });

  it("states the rule count and the gitleaks version in the README", () => {
    const readme = read("README.md");
    assert.ok(readme.includes(`${String(rules.length)} built-in rules`), "rule count");
    assert.ok(readme.includes(`gitleaks ${GITLEAKS_VERSION}`), "gitleaks version");
  });

  it("has an Unreleased section on top of the changelog", () => {
    assert.match(read("CHANGELOG.md"), /^# Changelog[\s\S]*?\n## \[Unreleased\]/u);
  });
});
