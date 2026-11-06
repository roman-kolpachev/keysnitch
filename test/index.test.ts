// Scenarios: the package's public API is exactly this list. Adding a name
// is a minor version; removing or renaming one is a major version.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as keysnitch from "../src/index.ts";

describe("public API", () => {
  it("exports exactly these names", () => {
    assert.deepEqual(Object.keys(keysnitch).sort(), [
      "PatternError",
      "RuleError",
      "UnsafePatternError",
      "defineRule",
      "findRules",
      "mask",
      "rules",
      "scan",
      "vendors",
    ]);
  });

  it("exports frozen built-in rules", () => {
    assert.ok(Object.isFrozen(keysnitch.rules));
    for (const rule of keysnitch.rules) {
      assert.ok(Object.isFrozen(rule), rule.id);
    }
  });
});
