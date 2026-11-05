// Writes a parsed pattern as JavaScript RegExp source. The result needs no
// flags for its meaning: case folding is already inside the character sets,
// "." is written as an explicit class, and ^ and $ mean the whole text.

import type { Node } from "./ast.ts";
import { negate, type CharSet } from "./charset.ts";

const SPECIAL_OUTSIDE = new Set([
  "\\",
  "^",
  "$",
  ".",
  "|",
  "?",
  "*",
  "+",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  "/",
  "-",
]);
const SPECIAL_INSIDE = new Set(["\\", "]", "^", "-", "["]);

function unit(code: number, special: ReadonlySet<string>): string {
  const c = String.fromCharCode(code);
  if (code < 0x20 || code > 0x7e) return `\\u${code.toString(16).padStart(4, "0")}`;
  return special.has(c) ? `\\${c}` : c;
}

function ranges(set: CharSet): string {
  return set
    .map(([low, high]) => {
      if (low === high) return unit(low, SPECIAL_INSIDE);
      return `${unit(low, SPECIAL_INSIDE)}-${unit(high, SPECIAL_INSIDE)}`;
    })
    .join("");
}

function charClass(set: CharSet): string {
  const first = set[0];
  if (set.length === 1 && first !== undefined && first[0] === first[1])
    return unit(first[0], SPECIAL_OUTSIDE);
  const negated = negate(set);
  return negated.length < set.length ? `[^${ranges(negated)}]` : `[${ranges(set)}]`;
}

function quantifier(min: number, max: number | null, lazy: boolean): string {
  const base =
    min === 0 && max === 1
      ? "?"
      : max === min
        ? `{${String(min)}}`
        : `{${String(min)},${max === null ? "" : String(max)}}`;
  return lazy ? `${base}?` : base;
}

/** Source for a node that must act as one unit (before a quantifier, inside a sequence). */
function atom(node: Node): string {
  if (node.kind === "seq" || node.kind === "alt") return `(?:${emit(node)})`;
  return emit(node);
}

export function emit(node: Node): string {
  switch (node.kind) {
    case "char":
      return charClass(node.set);
    case "seq":
      return node.items.map((item) => (item.kind === "alt" ? atom(item) : emit(item))).join("");
    case "alt":
      return node.options.map(emit).join("|");
    case "group": {
      const open = !node.capture ? "(?:" : node.name === undefined ? "(" : `(?<${node.name}>`;
      return `${open}${emit(node.node)})`;
    }
    case "repeat":
      return `${atom(node.node)}${quantifier(node.min, node.max, node.lazy)}`;
    case "assert":
      return { start: "^", end: "$", wordBoundary: "\\b", notWordBoundary: "\\B" }[node.what];
    case "look":
      return `(?${node.negative ? "!" : "="}${emit(node.node)})`;
  }
}
