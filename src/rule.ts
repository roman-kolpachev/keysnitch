import { compile, type CompiledPattern } from "./pattern/compile.ts";
import type { Rule, RuleSpec, Severity } from "./types.ts";

export class RuleError extends Error {
  constructor(id: string, message: string) {
    super(`rule ${JSON.stringify(id)}: ${message}`);
    this.name = "RuleError";
  }
}

export interface CompiledRule {
  readonly pattern: CompiledPattern;
  /** Allow patterns, searched in the secret. */
  readonly allow: readonly CompiledPattern[];
}

// The compiled parts live here, not on the rule, so a rule stays a plain
// object: it can be spread into a new spec, logged and compared.
const compiledRules = new WeakMap<Rule, CompiledRule>();

const SEVERITIES: readonly Severity[] = ["high", "medium", "low"];

/** Lower-case letters and digits in parts joined by single dashes. */
function isKebabCase(id: string): boolean {
  return id.split("-").every((part) => {
    if (part === "") return false;
    for (let index = 0; index < part.length; index += 1) {
      const c = part.charCodeAt(index);
      const letter = c >= 0x61 && c <= 0x7a;
      const digit = c >= 0x30 && c <= 0x39;
      if (!letter && !digit) return false;
    }
    return true;
  });
}

export function checkMetadata(spec: {
  readonly id: string;
  readonly vendor: string;
  readonly label: string;
  readonly severity: string;
}): void {
  if (!isKebabCase(spec.id)) throw new RuleError(spec.id, "the id must be kebab-case");
  if (spec.vendor.trim() === "") throw new RuleError(spec.id, "the vendor is empty");
  if (spec.label.trim() === "") throw new RuleError(spec.id, "the label is empty");
  if (!SEVERITIES.some((severity) => severity === spec.severity)) {
    throw new RuleError(spec.id, "the severity must be high, medium or low");
  }
}

function checkWords(id: string, words: readonly string[], what: string, lower: boolean): void {
  for (const word of words) {
    if (word.trim() === "") throw new RuleError(id, `an empty ${what}`);
    if (lower && word !== word.toLowerCase()) throw new RuleError(id, `${what} must be lower case`);
  }
}

/** Checks a rule and compiles its patterns. Throws RuleError, PatternError or UnsafePatternError. */
export function defineRule(spec: RuleSpec): Rule {
  checkMetadata(spec);
  checkWords(spec.id, spec.keywords, "keyword", true);
  checkWords(spec.id, spec.aliases ?? [], "alias", false);
  const minEntropy = spec.minEntropy ?? 0;
  if (!(minEntropy >= 0 && minEntropy <= 8))
    throw new RuleError(spec.id, "minEntropy must be between 0 and 8");
  const pattern = compile(spec.pattern);
  const secretGroup = spec.secretGroup ?? (pattern.groups > 0 ? "first" : 0);
  const known =
    secretGroup === "first" ||
    (Number.isInteger(secretGroup) && secretGroup >= 0 && secretGroup <= pattern.groups);
  if (!known) {
    throw new RuleError(spec.id, "the secret group is not in the pattern");
  }
  const allowSources = spec.allow ?? [];
  const allow = allowSources.map((source) => compile(source));

  const rule: Rule = Object.freeze({
    id: spec.id,
    vendor: spec.vendor,
    label: spec.label,
    severity: spec.severity,
    keywords: Object.freeze([...spec.keywords]),
    pattern: spec.pattern,
    secretGroup,
    minEntropy,
    aliases: Object.freeze([...(spec.aliases ?? [])]),
    allow: Object.freeze([...allowSources]),
    generic: spec.generic ?? false,
    ...(spec.rotate === undefined ? {} : { rotate: spec.rotate }),
    ...(spec.source === undefined ? {} : { source: spec.source }),
    ...(spec.validate === undefined ? {} : { validate: spec.validate }),
  });
  compiledRules.set(rule, Object.freeze({ pattern, allow: Object.freeze(allow) }));
  return rule;
}

/** The compiled parts of a rule made by defineRule; undefined for anything else. */
export function compiledRule(rule: Rule): CompiledRule | undefined {
  return compiledRules.get(rule);
}
