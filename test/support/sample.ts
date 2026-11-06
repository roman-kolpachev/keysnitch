// Builds random text that matches a rule pattern, straight from its parsed
// tree. Tests use it so the repository never holds real-looking keys:
// every example is made when the test runs.

import type { Node } from "#src/pattern/ast.ts";
import type { CharSet } from "#src/pattern/charset.ts";

/** A small seeded random generator (mulberry32), so failures repeat. */
export function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PREFERRED: readonly (readonly [number, number])[] = [
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x61, 0x7a],
];

/** Picks a character from the set: letters and digits when the set has them, else printable ASCII, else anything. */
function pick(set: CharSet, next: () => number): string {
  const tiers: (readonly [number, number])[][] = [[], [], []];
  for (const [low, high] of set) {
    for (const [from, to] of PREFERRED) {
      const a = Math.max(low, from);
      const b = Math.min(high, to);
      if (a <= b) {
        tiers[0]?.push([a, b]);
      }
    }
    const a = Math.max(low, 0x20);
    const b = Math.min(high, 0x7e);
    if (a <= b) {
      tiers[1]?.push([a, b]);
    }
    tiers[2]?.push([low, high]);
  }
  const ranges = tiers.find((tier) => tier.length > 0) ?? [];
  const total = ranges.reduce((sum, [low, high]) => sum + high - low + 1, 0);
  let index = Math.floor(next() * total);
  for (const [low, high] of ranges) {
    const width = high - low + 1;
    if (index < width) {
      return String.fromCharCode(low + index);
    }
    index -= width;
  }
  return "";
}

export function sample(node: Node, next: () => number): string {
  switch (node.kind) {
    case "char":
      return pick(node.set, next);
    case "seq":
      return node.items.map((item) => sample(item, next)).join("");
    case "alt": {
      const option = node.options[Math.floor(next() * node.options.length)];
      return option === undefined ? "" : sample(option, next);
    }
    case "group":
      return sample(node.node, next);
    case "repeat": {
      const top = Math.min(node.max ?? node.min + 20, node.min + 20);
      const count = node.min + Math.floor(next() * (top - node.min + 1));
      return Array.from({ length: count }, () => sample(node.node, next)).join("");
    }
    case "assert":
    case "look":
      return "";
  }
}

/** One character from every character set in the tree, for slow-input tests. */
export function characters(node: Node, next: () => number, out: Set<string> = new Set()): Set<string> {
  switch (node.kind) {
    case "char":
      out.add(pick(node.set, next));
      break;
    case "seq":
      node.items.forEach((item) => characters(item, next, out));
      break;
    case "alt":
      node.options.forEach((option) => characters(option, next, out));
      break;
    case "group":
    case "repeat":
    case "look":
      characters(node.node, next, out);
      break;
    case "assert":
      break;
  }
  return out;
}
