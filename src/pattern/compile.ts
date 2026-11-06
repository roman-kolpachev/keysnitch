// The only place in keysnitch that builds a RegExp. Every rule pattern goes
// through parse, the safety check and emit first (ESLint keeps it so).

import { check } from "./check.ts";
import { emit } from "./emit.ts";
import { parse } from "./parse.ts";
import type { Node } from "./ast.ts";

export class UnsafePatternError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`unsafe pattern: ${problems.join("; ")}`);
    this.name = "UnsafePatternError";
    this.problems = problems;
  }
}

export interface CompiledPattern {
  /** Global, with match indices. Use it through String.prototype.matchAll, which copies it. */
  readonly regex: RegExp;
  /** Number of capturing groups. */
  readonly groups: number;
  readonly tree: Node;
  readonly cost: number;
}

function countGroups(node: Node): number {
  switch (node.kind) {
    case "char":
    case "assert":
      return 0;
    case "group":
      return (node.capture ? 1 : 0) + countGroups(node.node);
    case "repeat":
    case "look":
      return countGroups(node.node);
    case "seq":
      return node.items.reduce((total, item) => total + countGroups(item), 0);
    case "alt":
      return node.options.reduce((total, option) => total + countGroups(option), 0);
  }
}

/** Parses, checks and builds a rule pattern. Throws PatternError or UnsafePatternError. */
export function compile(source: string): CompiledPattern {
  const tree = parse(source);
  const result = check(tree);
  if (result.problems.length > 0) {
    throw new UnsafePatternError(result.problems);
  }
  return { regex: new RegExp(emit(tree), "dg"), groups: countGroups(tree), tree, cost: result.cost };
}
