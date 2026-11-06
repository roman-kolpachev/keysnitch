// Turns a gitleaks pattern into one keysnitch accepts, without changing what
// it finds:
// - the leading "[\w.-]{0,50}?" that many gitleaks rules start with only
//   widens the match to the left of the keyword; the secret group does not
//   change, so it is dropped (it costs up to 50 steps per position);
// - unbounded repeats (+, *, {n,}) get the upper bound MAX_REPEAT.
// Patterns that still fail the safety check get a hand-written override.

import { MAX_REPEAT } from "../../src/pattern/check.ts";

const LEADING_CONTEXT = "[\\w.-]{0,50}?";

export function stripLeadingContext(source: string): string {
  if (source.startsWith(`(?i)${LEADING_CONTEXT}`)) {
    return `(?i)${source.slice(4 + LEADING_CONTEXT.length)}`;
  }
  if (source.startsWith(LEADING_CONTEXT)) {
    return source.slice(LEADING_CONTEXT.length);
  }
  return source;
}

/** Gives every unbounded repeat outside character classes the upper bound `cap`. */
export function boundRepeats(source: string, cap: number = MAX_REPEAT): string {
  let out = "";
  let inClass = false;
  let classStart = -1;
  for (let index = 0; index < source.length; index += 1) {
    const c = source.charAt(index);
    if (c === "\\") {
      out += source.slice(index, index + 2);
      index += 1;
      continue;
    }
    if (inClass) {
      if (c === "[" && source.startsWith("[:", index)) {
        const end = source.indexOf(":]", index + 2);
        out += source.slice(index, end + 2);
        index = end + 1;
        continue;
      }
      const atStart =
        index === classStart + 1 || (index === classStart + 2 && source.charAt(classStart + 1) === "^");
      if (c === "]" && !atStart) {
        inClass = false;
      }
      out += c;
      continue;
    }
    if (c === "[") {
      inClass = true;
      classStart = index;
      out += c;
      continue;
    }
    if (c === "+" || c === "*") {
      out += `{${c === "+" ? "1" : "0"},${String(cap)}}`;
      continue;
    }
    if (c === "{") {
      const match = /^\{(\d+),\}/u.exec(source.slice(index));
      if (match !== null) {
        out += `{${match[1] ?? "0"},${String(cap)}}`;
        index += match[0].length - 1;
        continue;
      }
    }
    out += c;
  }
  return out;
}
