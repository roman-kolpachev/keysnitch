// keysnitch: find leaked API keys, tokens and passwords in any text.

export { scan, type ScanOptions, type ScanResult } from "./scan.ts";
export { defineRule, RuleError } from "./rule.ts";
export { rules } from "./rules/index.ts";
export { findRules, vendors } from "./search.ts";
export { mask } from "./mask.ts";
export { PatternError } from "./pattern/parse.ts";
export { UnsafePatternError } from "./pattern/compile.ts";
export type { CustomMatcher, Finding, Rule, RuleSpec, Severity } from "./types.ts";
