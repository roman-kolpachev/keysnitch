import { rules as builtInRules } from "./rules/index.ts";
import type { Rule } from "./types.ts";

function words(rule: Rule): string[] {
  return [rule.vendor, rule.label, rule.id, ...rule.aliases].map((word) => word.toLowerCase());
}

function byVendorThenLabel(a: Rule, b: Rule): number {
  const vendor = a.vendor.localeCompare(b.vendor, "en");
  return vendor === 0 ? a.label.localeCompare(b.label, "en") : vendor;
}

/**
 * Finds rules by company, name, id or alias. Every word of the query must
 * match one of them, in part and in any case. A blank query returns all.
 */
export function findRules(query: string, rules: readonly Rule[] = builtInRules): Rule[] {
  const terms = query
    .toLowerCase()
    .split(" ")
    .filter((term) => term !== "");
  return rules
    .filter((rule) => {
      const fields = words(rule);
      return terms.every((term) => fields.some((field) => field.includes(term)));
    })
    .sort(byVendorThenLabel);
}

/** How many rules each company has, sorted by company name. */
export function vendors(rules: readonly Rule[] = builtInRules): { vendor: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const rule of rules) counts.set(rule.vendor, (counts.get(rule.vendor) ?? 0) + 1);
  return [...counts.entries()]
    .map(([vendor, count]) => ({ vendor, count }))
    .sort((a, b) => a.vendor.localeCompare(b.vendor, "en"));
}
