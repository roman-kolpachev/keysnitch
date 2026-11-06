// A parser for the pattern syntax of keysnitch rules: the RE2 syntax that
// gitleaks uses, minus everything that can make matching slow or
// unpredictable, plus a limited lookahead for boundaries.
//
// The parser is strict on purpose. A construct it does not know is an
// error, never a guess, so a rule always means exactly what its tree says.

import type { Node } from "./ast.ts";
import { charSet, foldAsciiCase, negate, union, type CharSet, type Range } from "./charset.ts";

export class PatternError extends Error {
  readonly position: number;

  constructor(message: string, position: number) {
    super(`${message} at ${String(position)}`);
    this.name = "PatternError";
    this.position = position;
  }
}

const MAX_PATTERN_LENGTH = 10_000;
const MAX_COUNT = 100_000;

const single = (c: string): Range => [c.charCodeAt(0), c.charCodeAt(0)];
const span = (from: string, to: string): Range => [from.charCodeAt(0), to.charCodeAt(0)];

const DIGIT: CharSet = charSet([span("0", "9")]);
const WORD: CharSet = charSet([span("0", "9"), span("A", "Z"), span("a", "z"), single("_")]);
// The JavaScript set of white space: wider than Go's [\t\n\f\r ], so a
// no-break space next to a credential still counts as a separator.
const SPACE: CharSet = charSet([
  [0x09, 0x0d],
  [0x20, 0x20],
  [0xa0, 0xa0],
  [0x1680, 0x1680],
  [0x2000, 0x200a],
  [0x2028, 0x2029],
  [0x202f, 0x202f],
  [0x205f, 0x205f],
  [0x3000, 0x3000],
  [0xfeff, 0xfeff],
]);
const LINE_FEED: CharSet = charSet([[0x0a, 0x0a]]);
const ANY: CharSet = negate([]);

const POSIX: Readonly<Record<string, CharSet>> = {
  alnum: charSet([span("0", "9"), span("A", "Z"), span("a", "z")]),
  alpha: charSet([span("A", "Z"), span("a", "z")]),
  digit: DIGIT,
  lower: charSet([span("a", "z")]),
  upper: charSet([span("A", "Z")]),
  space: charSet([[0x09, 0x0d], single(" ")]),
  xdigit: charSet([span("0", "9"), span("A", "F"), span("a", "f")]),
  punct: charSet([
    [0x21, 0x2f],
    [0x3a, 0x40],
    [0x5b, 0x60],
    [0x7b, 0x7e],
  ]),
  word: WORD,
};

const CONTROL_ESCAPES: Readonly<Record<string, number>> = { t: 9, n: 10, v: 11, f: 12, r: 13 };
const SHORTHAND: Readonly<Record<string, CharSet>> = {
  d: DIGIT,
  D: negate(DIGIT),
  w: WORD,
  W: negate(WORD),
  s: SPACE,
  S: negate(SPACE),
};
const GROUP_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;

interface Flags {
  readonly ignoreCase: boolean;
  readonly dotAll: boolean;
}

function isPunctuation(c: string): boolean {
  const unit = c.charCodeAt(0);
  return (
    (unit >= 0x21 && unit <= 0x2f) ||
    (unit >= 0x3a && unit <= 0x40) ||
    (unit >= 0x5b && unit <= 0x60) ||
    (unit >= 0x7b && unit <= 0x7e)
  );
}

class Parser {
  private position = 0;
  private groups = 0;
  private readonly names = new Set<string>();
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  run(): Node {
    const node = this.alternation({ ignoreCase: false, dotAll: false }, false);
    if (this.position < this.source.length) throw this.error("unmatched )");
    return node;
  }

  private error(message: string, at = this.position): PatternError {
    return new PatternError(message, at);
  }

  private peek(offset = 0): string | undefined {
    return this.source[this.position + offset];
  }

  private next(): string {
    const c = this.source[this.position];
    if (c === undefined) throw this.error("unexpected end of pattern");
    this.position += 1;
    return c;
  }

  private startsWith(text: string): boolean {
    return this.source.startsWith(text, this.position);
  }

  /** Parses options separated by "|" until ")" or the end. */
  private alternation(initial: Flags, inLook: boolean): Node {
    const flags = { current: initial };
    const options: Node[] = [this.sequence(flags, inLook)];
    while (this.peek() === "|") {
      this.position += 1;
      options.push(this.sequence(flags, inLook));
    }
    return options.length === 1 && options[0] !== undefined ? options[0] : { kind: "alt", options };
  }

  private sequence(flags: { current: Flags }, inLook: boolean): Node {
    const items: Node[] = [];
    let repeatable = false;
    for (let c = this.peek(); c !== undefined && c !== "|" && c !== ")"; c = this.peek()) {
      const start = this.position;
      const quantifier = this.quantifier();
      if (quantifier !== undefined) {
        const last = items.pop();
        if (!repeatable || last === undefined) throw this.error("nothing to repeat", start);
        items.push({ kind: "repeat", node: last, ...quantifier });
        repeatable = false;
        continue;
      }
      const atom = this.atom(flags, inLook);
      if (atom === "flags") continue;
      items.push(atom.node);
      repeatable = atom.repeatable;
    }
    return items.length === 1 && items[0] !== undefined ? items[0] : { kind: "seq", items };
  }

  /** Reads a quantifier at the current position, if there is one. */
  private quantifier(): { min: number; max: number | null; lazy: boolean } | undefined {
    const c = this.peek();
    let min: number;
    let max: number | null;
    if (c === "?" || c === "*" || c === "+") {
      this.position += 1;
      min = c === "+" ? 1 : 0;
      max = c === "?" ? 1 : null;
    } else if (c === "{") {
      const counts = this.braces();
      if (counts === undefined) return undefined;
      [min, max] = counts;
    } else {
      return undefined;
    }
    const lazy = this.peek() === "?";
    if (lazy) this.position += 1;
    return { min, max, lazy };
  }

  /** {n}, {n,} or {n,m}; anything else is not a quantifier (RE2 reads it literally). */
  private braces(): [number, number | null] | undefined {
    const match = /^\{(\d+)(,(\d*))?\}/u.exec(this.source.slice(this.position));
    if (match === null) return undefined;
    const [whole, low, comma, high] = match;
    const start = this.position;
    const min = Number(low);
    const max = comma === undefined ? min : high === "" || high === undefined ? null : Number(high);
    if (min > MAX_COUNT || (max !== null && max > MAX_COUNT))
      throw this.error("repeat count above 100000", start);
    if (max !== null && min > max) throw this.error("repeat range with min above max", start);
    this.position += whole.length;
    return [min, max];
  }

  private atom(flags: { current: Flags }, inLook: boolean): "flags" | { node: Node; repeatable: boolean } {
    const start = this.position;
    const c = this.next();
    switch (c) {
      case "(":
        return this.group(flags, inLook, start);
      case "[":
        return { node: { kind: "char", set: this.charClass(flags.current) }, repeatable: true };
      case ".":
        return {
          node: { kind: "char", set: flags.current.dotAll ? ANY : negate(LINE_FEED) },
          repeatable: true,
        };
      case "^":
        return { node: { kind: "assert", what: "start" }, repeatable: false };
      case "$":
        return { node: { kind: "assert", what: "end" }, repeatable: false };
      case "\\":
        return this.escape(flags.current, start);
      default:
        return {
          node: { kind: "char", set: this.fold(charSet([single(c)]), flags.current) },
          repeatable: true,
        };
    }
  }

  private fold(set: CharSet, flags: Flags): CharSet {
    return flags.ignoreCase ? foldAsciiCase(set) : set;
  }

  private escape(flags: Flags, start: number): { node: Node; repeatable: boolean } {
    const c = this.next();
    const assertion = { A: "start", z: "end", b: "wordBoundary", B: "notWordBoundary" } as const;
    if (c === "A" || c === "z" || c === "b" || c === "B") {
      return { node: { kind: "assert", what: assertion[c] }, repeatable: false };
    }
    const shorthand = SHORTHAND[c];
    if (shorthand !== undefined)
      return { node: { kind: "char", set: this.fold(shorthand, flags) }, repeatable: true };
    return {
      node: { kind: "char", set: this.fold(charSet([this.literalEscape(c, start)]), flags) },
      repeatable: true,
    };
  }

  /** An escape that stands for one character: punctuation, controls, hex. */
  private literalEscape(c: string, start: number): Range {
    if (isPunctuation(c)) return single(c);
    const control = CONTROL_ESCAPES[c];
    if (control !== undefined) return [control, control];
    if (c === "x") {
      const unit = this.hex(start);
      return [unit, unit];
    }
    throw this.error(`unknown escape \\${c}`, start);
  }

  private hex(start: number): number {
    const braced = /^\{([0-9A-Fa-f]{1,6})\}/u.exec(this.source.slice(this.position));
    const plain = /^[0-9A-Fa-f]{2}/u.exec(this.source.slice(this.position));
    const match = braced ?? plain;
    if (match === null) throw this.error("bad hex escape", start);
    const value = Number.parseInt(braced?.[1] ?? match[0], 16);
    if (value > 0xffff) throw this.error("hex escape above 0xFFFF", start);
    this.position += match[0].length;
    return value;
  }

  /** Folds case before negating, like RE2: (?i)[^a] matches neither "a" nor "A". */
  private charClass(flags: Flags): CharSet {
    const start = this.position - 1;
    const negated = this.peek() === "^";
    if (negated) this.position += 1;
    let set: CharSet = [];
    let first = true;
    while (this.peek() !== "]" || first) {
      if (this.peek() === undefined) throw this.error("unclosed character class", start);
      first = false;
      set = union(set, this.classItem(start));
    }
    this.position += 1;
    const folded = this.fold(set, flags);
    return negated ? negate(folded) : folded;
  }

  private classItem(classStart: number): CharSet {
    if (this.startsWith("[:")) {
      const match = /^\[:[a-z]+:\]/u.exec(this.source.slice(this.position));
      const posix = match === null ? undefined : POSIX[match[0].slice(2, -2)];
      if (match === null || posix === undefined) throw this.error("unknown POSIX class");
      this.position += match[0].length;
      return posix;
    }
    const low = this.classAtom();
    if (this.peek() === "-" && this.peek(1) !== "]" && this.peek(1) !== undefined) {
      const dash = this.position;
      this.position += 1;
      const high = this.classAtom();
      if (typeof low !== "number" || typeof high !== "number")
        throw this.error("range with a class at its end", dash);
      if (low > high) throw this.error("reversed range", dash);
      return charSet([[low, high]]);
    }
    if (this.peek() === undefined) throw this.error("unclosed character class", classStart);
    return typeof low === "number" ? charSet([[low, low]]) : low;
  }

  /** One class member: a code unit, or a whole set for \d, \w, \s and friends. */
  private classAtom(): number | CharSet {
    const start = this.position;
    const c = this.next();
    if (c !== "\\") return c.charCodeAt(0);
    const e = this.next();
    const shorthand = SHORTHAND[e];
    if (shorthand !== undefined) return shorthand;
    return this.literalEscape(e, start)[0];
  }

  private group(
    flags: { current: Flags },
    inLook: boolean,
    start: number,
  ): "flags" | { node: Node; repeatable: boolean } {
    if (this.peek() !== "?") return this.capture(flags.current, inLook, start, undefined);
    this.position += 1;
    if (this.startsWith("P<") || (this.peek() === "<" && this.peek(1) !== "=" && this.peek(1) !== "!")) {
      this.position += this.peek() === "P" ? 2 : 1;
      const end = this.source.indexOf(">", this.position);
      if (end === -1) throw this.error("unclosed group name", start);
      const name = this.source.slice(this.position, end);
      if (!GROUP_NAME.test(name)) throw this.error("bad group name", start);
      if (this.names.has(name)) throw this.error("duplicate group name", start);
      this.names.add(name);
      this.position = end + 1;
      return this.capture(flags.current, inLook, start, name);
    }
    if (this.peek() === "=" || this.peek() === "!") {
      const negative = this.next() === "!";
      const node = this.alternation(flags.current, true);
      this.close(start);
      return { node: { kind: "look", negative, node }, repeatable: false };
    }
    return this.flagGroup(flags, inLook, start);
  }

  private capture(
    flags: Flags,
    inLook: boolean,
    start: number,
    name: string | undefined,
  ): { node: Node; repeatable: boolean } {
    if (inLook) throw this.error("capture inside a lookahead", start);
    this.groups += 1;
    const index = this.groups;
    const node = this.alternation(flags, inLook);
    this.close(start);
    this.checkNotEmpty(node, start);
    const group: Node =
      name === undefined
        ? { kind: "group", capture: true, index, node }
        : { kind: "group", capture: true, index, name, node };
    return { node: group, repeatable: true };
  }

  /** (?i) (?s) (?-i) (?i:...) and similar. Only the i and s flags exist. */
  private flagGroup(
    flags: { current: Flags },
    inLook: boolean,
    start: number,
  ): "flags" | { node: Node; repeatable: boolean } {
    const match = /^[is]*(?:-[is]*)?[:)]/u.exec(this.source.slice(this.position));
    if (match === null) throw this.error("unknown group or flag", start);
    const whole = match[0];
    const body = whole.slice(0, -1);
    const dash = body.indexOf("-");
    const on = dash === -1 ? body : body.slice(0, dash);
    const off = dash === -1 ? "" : body.slice(dash + 1);
    const end = whole.endsWith(")") ? ")" : ":";
    if (end === ")" && on === "" && off === "") throw this.error("empty flag group", start);
    const updated: Flags = {
      ignoreCase: on.includes("i") ? true : off.includes("i") ? false : flags.current.ignoreCase,
      dotAll: on.includes("s") ? true : off.includes("s") ? false : flags.current.dotAll,
    };
    this.position += whole.length;
    if (end === ")") {
      flags.current = updated;
      return "flags";
    }
    const node = this.alternation(updated, inLook);
    this.close(start);
    this.checkNotEmpty(node, start);
    return { node: { kind: "group", capture: false, index: 0, node }, repeatable: true };
  }

  private close(start: number): void {
    if (this.peek() !== ")") throw this.error("unclosed group", start);
    this.position += 1;
  }

  private checkNotEmpty(node: Node, start: number): void {
    if (node.kind === "seq" && node.items.length === 0) {
      // An empty group can only be there to be repeated or to confuse.
      throw this.error("empty group", start);
    }
  }
}

/** Parses a rule pattern. Throws PatternError for anything it does not accept. */
export function parse(source: string): Node {
  if (source.length === 0) throw new PatternError("empty pattern", 0);
  if (source.length > MAX_PATTERN_LENGTH) throw new PatternError("pattern longer than 10000 characters", 0);
  return new Parser(source).run();
}
