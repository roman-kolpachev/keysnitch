// Converts the vendored gitleaks config into keysnitch rule specs. Used by
// tools/gitleaks/import.ts (writes src/rules/gitleaks.ts) and by the tests,
// which check that the written file is up to date.

import { readFileSync } from "node:fs";
import { defineRule } from "#src/rule.ts";
import type { RuleSpec } from "#src/types.ts";
import { boundRepeats, stripLeadingContext } from "./convert.ts";
import { ALSO } from "./also.ts";
import { OVERRIDES, SKIPPED } from "./overrides.ts";
import { ROTATE } from "./rotate.ts";
import { parseGitleaksToml, type GitleaksRule } from "./toml.ts";
import { ALIASES, labelOf, severityOf, vendorOf } from "./vendors.ts";

const root = new URL("../../", import.meta.url);
const version = readFileSync(new URL("third_party/gitleaks/VERSION", root), "utf8").trim();
const gitleaks = parseGitleaksToml(readFileSync(new URL("third_party/gitleaks/gitleaks.toml", root), "utf8"));

function allowOf(rule: GitleaksRule): string[] {
  // Only allowlists aimed at the secret (the default target) carry over:
  // keysnitch has no file paths, and "match"/"line" targets belong to the
  // generic rule that keysnitch replaces with its own.
  return rule.allowlists
    .filter((list) => list.regexTarget === undefined || list.regexTarget === "secret")
    .flatMap((list) => list.regexes.map((regex) => boundRepeats(regex)));
}

function convert(rule: GitleaksRule): RuleSpec | string {
  const skipped = SKIPPED[rule.id];
  if (skipped !== undefined) {
    return skipped;
  }
  if (rule.regex === undefined) {
    return "no pattern (a file path rule)";
  }
  const override = OVERRIDES[rule.id];
  const base = override?.pattern ?? boundRepeats(stripLeadingContext(rule.regex));
  const also = ALSO[rule.id];
  // The wider shape goes first: at one position an alternation takes the first branch that matches.
  const pattern = also === undefined ? base : `(?:${also.pattern})|(?:${base})`;
  const { vendor } = vendorOf(rule.id);
  const aliases = ALIASES[vendor] ?? [];
  const allow = override?.allow ?? allowOf(rule);
  const secretGroup = override?.secretGroup ?? rule.secretGroup;
  const keywords = override?.keywords ?? rule.keywords.map((keyword) => keyword.toLowerCase());
  const rotate = ROTATE[rule.id];
  return {
    id: rule.id,
    vendor,
    label: labelOf(rule.id),
    severity: severityOf(rule.id),
    keywords: [...new Set([...keywords, ...(also?.keywords ?? [])])],
    pattern,
    ...(rotate === undefined ? {} : { rotate }),
    ...(secretGroup === undefined ? {} : { secretGroup }),
    ...(rule.entropy === undefined ? {} : { minEntropy: rule.entropy }),
    ...(aliases.length === 0 ? {} : { aliases }),
    ...(allow.length === 0 ? {} : { allow }),
    ...(vendor === "Generic" ? { generic: true } : {}),
    source: `gitleaks ${version}: ${rule.id}`,
  };
}

export interface GitleaksBuild {
  readonly version: string;
  /** Every rule id in the vendored gitleaks config. */
  readonly ids: readonly string[];
  readonly specs: readonly RuleSpec[];
  readonly skipped: readonly { readonly id: string; readonly reason: string }[];
  readonly failures: readonly string[];
}

export function buildGitleaksRules(): GitleaksBuild {
  const specs: RuleSpec[] = [];
  const skipped: { id: string; reason: string }[] = [];
  const failures: string[] = [];
  for (const rule of gitleaks) {
    const result = convert(rule);
    if (typeof result === "string") {
      skipped.push({ id: rule.id, reason: result });
      continue;
    }
    try {
      defineRule(result);
      specs.push(result);
    } catch (error) {
      failures.push(
        `${rule.id}: ${error instanceof Error ? error.message : "unknown error"}\n    ${result.pattern}`,
      );
    }
  }
  return { version, ids: gitleaks.map((rule) => rule.id), specs, skipped, failures };
}
