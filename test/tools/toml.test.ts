// Scenarios: the importer reads gitleaks.toml exactly, and fails loudly on
// anything it does not know (a new gitleaks format must be looked at).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseGitleaksToml } from "../../tools/gitleaks/toml.ts";

const sample = `
title = "gitleaks config"
# a comment
[allowlist]
regexes = ['''^skip$''']

[[rules]]
id = "demo-token"
description = "A \\"demo\\" token"
regex = '''\\bdmo_[a-z]{8}'''
entropy = 3.5
secretGroup = 1
keywords = [
    "dmo_", # trailing comment
    'raw',
]

[[rules.allowlists]]
regexTarget = "match"
regexes = ['''x+''']
stopwords = ["example"]
paths = ['''\\.md$''']

[[rules]]
id = "path-only"
description = "A file"
path = '''\\.p12$'''
keywords = []
`;

describe("parseGitleaksToml", () => {
  it("reads rules, values and allowlists", () => {
    const rules = parseGitleaksToml(sample);
    assert.equal(rules.length, 2);
    assert.deepEqual(rules[0], {
      id: "demo-token",
      description: 'A "demo" token',
      regex: "\\bdmo_[a-z]{8}",
      keywords: ["dmo_", "raw"],
      entropy: 3.5,
      secretGroup: 1,
      allowlists: [{ regexes: ["x+"], regexTarget: "match", stopwords: ["example"], paths: ["\\.md$"] }],
    });
    assert.deepEqual(rules[1], {
      id: "path-only",
      description: "A file",
      path: "\\.p12$",
      keywords: [],
      allowlists: [],
    });
  });

  it("refuses unknown tables and keys", () => {
    assert.throws(() => parseGitleaksToml("[extend]\n"), /unknown table/u);
    assert.throws(() => parseGitleaksToml('[[rules]]\nid = "a"\ncolor = "red"\n'), /unknown rule key/u);
    assert.throws(() => parseGitleaksToml("[[rules.allowlists]]\n"), /outside a rule/u);
  });

  it("reads the vendored gitleaks config with 222 rules", () => {
    const text = readFileSync(new URL("../../third_party/gitleaks/gitleaks.toml", import.meta.url), "utf8");
    const rules = parseGitleaksToml(text);
    assert.equal(rules.length, 222);
    assert.equal(new Set(rules.map((rule) => rule.id)).size, 222);
  });
});
