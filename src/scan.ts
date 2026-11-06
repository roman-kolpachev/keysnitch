import { entropy } from "./entropy.ts";
import { isPlaceholder } from "./placeholder.ts";
import { checkMetadata, compiledRule } from "./rule.ts";
import { rules as builtInRules } from "./rules/index.ts";
import type { CustomMatcher, Finding, Rule } from "./types.ts";

export type { Finding } from "./types.ts";

export interface ScanOptions {
  /** The rules to run. Default: every built-in rule. */
  readonly rules?: readonly Rule[];
  /** Extra matchers written in code. */
  readonly matchers?: readonly CustomMatcher[];
  /** Stop after this many findings. Default 1000. */
  readonly maxFindings?: number;
  /** Return true to skip a value, for example one the user marked as safe. */
  readonly ignore?: (value: string, finding: Finding) => boolean;
}

export interface ScanResult {
  /** Sorted by start, never overlapping. */
  readonly findings: readonly Finding[];
  /** False when maxFindings stopped the scan early. */
  readonly complete: boolean;
}

const DEFAULT_MAX_FINDINGS = 1000;

interface Candidate extends Finding {
  readonly generic: boolean;
}

/**
 * The range of the secret in a match: a numbered group, or the first group
 * that took part. Exported for tests only (not part of the public API).
 */
export function secretRange(
  match: RegExpExecArray,
  group: number | "first",
): readonly [number, number] | undefined {
  // Compiled patterns have the "d" flag; a match without indices has no range.
  const indices = match.indices ?? [];
  if (group !== "first") return indices[group];
  for (let index = 1; index < indices.length; index += 1) {
    const range = indices[index];
    if (range !== undefined) return range;
  }
  // No group took part: the whole match is the secret, as in gitleaks.
  return indices[0];
}

function ruleMatches(text: string, rule: Rule): Candidate[] {
  const compiled = compiledRule(rule);
  if (compiled === undefined)
    throw new TypeError(`rule ${JSON.stringify(rule.id)} was not made by defineRule`);
  const found: Candidate[] = [];
  for (const match of text.matchAll(compiled.pattern.regex)) {
    const range = secretRange(match, rule.secretGroup);
    if (range === undefined) continue;
    const [start, end] = range;
    if (start === end) continue;
    const secret = text.slice(start, end);
    if (rule.minEntropy > 0 && entropy(secret) < rule.minEntropy) continue;
    if (compiled.allow.some((allow) => secret.search(allow.regex) !== -1)) continue;
    if (rule.validate !== undefined && !rule.validate(secret)) continue;
    found.push({
      ruleId: rule.id,
      vendor: rule.vendor,
      label: rule.label,
      severity: rule.severity,
      start,
      end,
      generic: rule.generic,
    });
  }
  return found;
}

function matcherMatches(text: string, matcher: CustomMatcher): Candidate[] {
  checkMetadata(matcher);
  const found: Candidate[] = [];
  for (const { start, end } of matcher.find(text)) {
    const valid =
      Number.isInteger(start) && Number.isInteger(end) && start >= 0 && start < end && end <= text.length;
    if (!valid) throw new RangeError(`custom matcher ${JSON.stringify(matcher.id)} returned a bad range`);
    const { id, vendor, label, severity } = matcher;
    found.push({ ruleId: id, vendor, label, severity, start, end, generic: false });
  }
  return found;
}

/**
 * Which rule names a joined range: a specific rule before a generic one
 * (the label says what the credential is), then the wider match, then by id.
 * The range itself is always the union of all candidates.
 */
function better(a: Candidate, b: Candidate): Candidate {
  if (a.generic !== b.generic) return a.generic ? b : a;
  const widthA = a.end - a.start;
  const widthB = b.end - b.start;
  if (widthA !== widthB) return widthA > widthB ? a : b;
  return a.ruleId <= b.ruleId ? a : b;
}

/** Joins overlapping candidates into one finding each, so no part of a secret is left out. */
function resolve(candidates: readonly Candidate[]): Finding[] {
  const sorted = [...candidates].sort((a, b) => (a.start === b.start ? b.end - a.end : a.start - b.start));
  const result: Finding[] = [];
  let current: { start: number; end: number; best: Candidate } | undefined;
  const flush = (): void => {
    if (current === undefined) return;
    const { ruleId, vendor, label, severity } = current.best;
    result.push({ ruleId, vendor, label, severity, start: current.start, end: current.end });
  };
  for (const candidate of sorted) {
    if (current !== undefined && candidate.start < current.end) {
      current.end = Math.max(current.end, candidate.end);
      current.best = better(current.best, candidate);
    } else {
      flush();
      current = { start: candidate.start, end: candidate.end, best: candidate };
    }
  }
  flush();
  return result;
}

/** Finds credentials in a text. Never throws for any string, and never puts a found value in an error. */
export function scan(text: string, options: ScanOptions = {}): ScanResult {
  if (typeof text !== "string") throw new TypeError("scan() needs a string");
  const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  if (!Number.isInteger(maxFindings) || maxFindings < 1)
    throw new RangeError("maxFindings must be a positive whole number");
  const lower = text.toLowerCase();
  const candidates: Candidate[] = [];
  for (const rule of options.rules ?? builtInRules) {
    if (rule.keywords.length > 0 && !rule.keywords.some((keyword) => lower.includes(keyword))) continue;
    candidates.push(...ruleMatches(text, rule));
  }
  for (const matcher of options.matchers ?? []) candidates.push(...matcherMatches(text, matcher));

  const ignore = options.ignore;
  const kept = candidates.filter((candidate) => {
    const value = text.slice(candidate.start, candidate.end);
    if (isPlaceholder(value)) return false;
    return ignore === undefined || !ignore(value, withoutGeneric(candidate));
  });
  const findings = resolve(kept);
  const complete = findings.length <= maxFindings;
  return { findings: complete ? findings : findings.slice(0, maxFindings), complete };
}

function withoutGeneric(candidate: Candidate): Finding {
  const { ruleId, vendor, label, severity, start, end } = candidate;
  return { ruleId, vendor, label, severity, start, end };
}
