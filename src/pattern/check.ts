// The safety check for rule patterns.
//
// keysnitch runs its rules with the built-in RegExp engine, which
// backtracks. Backtracking is only dangerous when a pattern lets the engine
// try very many ways to split the same text. This check refuses the shapes
// that allow that, so every rule has a small upper bound on the work per
// start position, and a whole scan stays linear in the length of the text.
//
// The rules (docs/decisions.md explains each one):
// 1. every repeat has an upper bound, at most MAX_REPEAT;
// 2. a repeat that can run more than once has a body of fixed length;
// 3. a lookahead holds only single characters or the end of text;
// 4. a rule never matches empty text;
// 5. the cost estimate (see sequenceCost) stays at or below MAX_COST.

import type { Node } from "./ast.ts";
import { intersects, union, type CharSet } from "./charset.ts";

export const MAX_REPEAT = 4096;
export const MAX_COST = 100_000;

export interface CheckResult {
  readonly problems: readonly string[];
  /** Upper estimate of backtracking steps per start position. */
  readonly cost: number;
}

function minLength(node: Node): number {
  switch (node.kind) {
    case "char":
      return 1;
    case "assert":
    case "look":
      return 0;
    case "group":
      return minLength(node.node);
    case "seq":
      return node.items.reduce((total, item) => total + minLength(item), 0);
    case "alt":
      return Math.min(...node.options.map(minLength));
    case "repeat":
      return minLength(node.node) * node.min;
  }
}

/** null means unbounded. */
function maxLength(node: Node): number | null {
  switch (node.kind) {
    case "char":
      return 1;
    case "assert":
    case "look":
      return 0;
    case "group":
      return maxLength(node.node);
    case "seq":
      return sumOrNull(node.items.map(maxLength));
    case "alt":
      return maxOrNull(node.options.map(maxLength));
    case "repeat": {
      const inner = maxLength(node.node);
      return inner === null || node.max === null ? null : inner * node.max;
    }
  }
}

function sumOrNull(values: readonly (number | null)[]): number | null {
  let total = 0;
  for (const value of values) {
    if (value === null) return null;
    total += value;
  }
  return total;
}

function maxOrNull(values: readonly (number | null)[]): number | null {
  let best = 0;
  for (const value of values) {
    if (value === null) return null;
    best = Math.max(best, value);
  }
  return best;
}

function isVariable(node: Node): boolean {
  return maxLength(node) !== minLength(node);
}

function isNullable(node: Node): boolean {
  return minLength(node) === 0;
}

/** The characters a match of the node can start with. */
function first(node: Node): CharSet {
  return edge(node, (items) => items);
}

/** The characters a match of the node can end with. */
function last(node: Node): CharSet {
  return edge(node, (items) => [...items].reverse());
}

function edge(node: Node, order: (items: readonly Node[]) => readonly Node[]): CharSet {
  switch (node.kind) {
    case "char":
      return node.set;
    case "assert":
    case "look":
      return [];
    case "group":
    case "repeat":
      return edge(node.node, order);
    case "alt":
      return node.options.reduce<CharSet>((set, option) => union(set, edge(option, order)), []);
    case "seq": {
      let set: CharSet = [];
      for (const item of order(node.items)) {
        set = union(set, edge(item, order));
        if (!isNullable(item)) break;
      }
      return set;
    }
  }
}

function firstOfRest(items: readonly Node[], from: number): CharSet {
  return first({ kind: "seq", items: items.slice(from) });
}

/** Estimated backtracking steps per start position (see the file header). */
function cost(node: Node): number {
  switch (node.kind) {
    case "char":
    case "assert":
    case "look":
      return 1;
    case "group":
      return cost(node.node);
    case "alt":
      return node.options.reduce((total, option) => total + cost(option), 0);
    case "repeat":
      return cost(node.node) * ((node.max ?? MAX_REPEAT) - node.min + 1);
    case "seq":
      return sequenceCost(node.items);
  }
}

/** How many different lengths a match of the node can have. */
function ways(node: Node): number {
  const min = minLength(node);
  return (maxLength(node) ?? min + MAX_REPEAT) - min + 1;
}

/**
 * The steps of every item, plus one product per chain of neighbours that
 * can trade characters: the earlier one has a variable length and can end
 * with a character the rest can start with, so the engine may try every
 * split between them. The product counts the possible lengths of each
 * item in the chain. An optional item keeps a chain going.
 */
function sequenceCost(items: readonly Node[]): number {
  let total = 0;
  let product = 1;
  let inChain = false;
  // The characters the chain so far can end with.
  let chainLast: CharSet = [];
  items.forEach((item, index) => {
    total += cost(item);
    if (inChain) product *= ways(item);
    const next = firstOfRest(items, index + 1);
    const trades = isVariable(item) && intersects(last(item), next);
    // An optional item lets earlier items meet later ones, but only on
    // characters both can take.
    const carries = inChain && isNullable(item) && intersects(chainLast, next);
    if ((trades || carries) && !inChain) {
      product = ways(item);
      inChain = true;
      chainLast = last(item);
    } else if (trades || carries) {
      chainLast = union(chainLast, last(item));
    } else if (inChain) {
      total += product;
      product = 1;
      inChain = false;
      chainLast = [];
    }
  });
  // The last item has nothing after it, so every chain is closed by now.
  return total;
}

function isLookaheadAtom(node: Node): boolean {
  return node.kind === "char" || (node.kind === "assert" && node.what === "end");
}

function collect(node: Node, problems: string[]): void {
  switch (node.kind) {
    case "char":
    case "assert":
      return;
    case "group":
      collect(node.node, problems);
      return;
    case "seq":
      node.items.forEach((item) => {
        collect(item, problems);
      });
      return;
    case "alt":
      node.options.forEach((option) => {
        collect(option, problems);
      });
      return;
    case "look": {
      const atoms = node.node.kind === "alt" ? node.node.options : [node.node];
      if (!atoms.every(isLookaheadAtom))
        problems.push("a lookahead may only hold single characters or the end of text");
      return;
    }
    case "repeat":
      if (node.max === null) problems.push("repeat with no upper bound");
      else if (node.max > MAX_REPEAT) problems.push(`repeat bound above ${String(MAX_REPEAT)}`);
      if ((node.max === null || node.max > 1) && isVariable(node.node)) {
        problems.push("a repeated part has a variable length inside");
      }
      collect(node.node, problems);
      return;
  }
}

/** Checks a parsed pattern against the safety rules. */
export function check(node: Node): CheckResult {
  const problems: string[] = [];
  collect(node, problems);
  if (minLength(node) === 0) problems.push("the pattern can match empty text");
  const estimate = cost(node);
  if (estimate > MAX_COST)
    problems.push(`too much backtracking: cost ${String(estimate)} above ${String(MAX_COST)}`);
  return { problems, cost: estimate };
}
