// Compiled by npm run check:consumer against the built package, the way a
// project with older module settings (CommonJS, node10) and a modern one
// (NodeNext) would use it.
import { defineRule, findRules, mask, rules, scan, type Finding, type Rule } from "../../dist/index.js";

const found: readonly Finding[] = scan("text").findings;
const all: readonly Rule[] = rules;
const own: Rule = defineRule({
  id: "x-y",
  vendor: "X",
  label: "X",
  severity: "low",
  keywords: ["x"],
  pattern: "x[0-9]{4}",
});
export const summary = [found.length, all.length, own.id, mask("abcdefghijklmnop"), findRules("x").length];
