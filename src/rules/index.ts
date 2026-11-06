import { defineRule } from "../rule.ts";
import type { Rule, RuleSpec } from "../types.ts";
import { gitleaksRules } from "./gitleaks.ts";
import { keysnitchRules } from "./keysnitch.ts";

function build(specs: readonly RuleSpec[]): readonly Rule[] {
  return Object.freeze(specs.map((spec) => defineRule(spec)));
}

/** Every built-in rule: the rules adapted from gitleaks, then keysnitch's own. */
export const rules: readonly Rule[] = build([...gitleaksRules, ...keysnitchRules]);
