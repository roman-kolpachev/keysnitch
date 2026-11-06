// Scenarios: rules are written in the RE2 syntax that gitleaks uses, and the
// parser turns a rule into a tree the safety check can reason about.
// - literals, escapes, classes, POSIX classes, groups, alternation,
//   quantifiers (greedy and lazy), anchors and word boundaries parse into
//   the expected nodes;
// - case-insensitive parts ((?i), (?i:...), (?-i:...)) are folded into the
//   character sets at parse time, ASCII only;
// - (?s) changes what "." means; "." never matches "\n" otherwise;
// - \s is the JavaScript set of white space (wider than Go's), \w and \d
//   are ASCII;
// - a limited lookahead is allowed for boundaries;
// - everything that can make matching slow or unpredictable is refused
//   with a clear error: backreferences, lookbehind, unknown escapes and
//   flags, unbalanced parentheses and brackets, a quantifier with nothing
//   to repeat, a {m,n} with m > n, numbers that are too large.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parse, PatternError } from "../../src/pattern/parse.ts";
import type { Node } from "../../src/pattern/ast.ts";
import { contains, type CharSet } from "../../src/pattern/charset.ts";

const code = (c: string): number => c.charCodeAt(0);

function setOf(node: Node): CharSet {
  if (node.kind !== "char") {
    throw new Error(`expected a char node, got ${node.kind}`);
  }
  return node.set;
}

function items(node: Node): readonly Node[] {
  return node.kind === "seq" ? node.items : [node];
}

function only(node: Node): Node {
  const list = items(node);
  assert.equal(list.length, 1);
  const first = list[0];
  if (first === undefined) {
    throw new Error("no node");
  }
  return first;
}

function charsOf(pattern: string): string[] {
  return items(parse(pattern)).map((node) => {
    const set = setOf(node);
    return set.map(([low, high]) => `${String.fromCharCode(low)}-${String.fromCharCode(high)}`).join(",");
  });
}

describe("literals and escapes", () => {
  it("parses plain text into one char node per character", () => {
    assert.deepEqual(charsOf("ab_"), ["a-a", "b-b", "_-_"]);
  });

  it("parses escaped metacharacters as literals", () => {
    assert.deepEqual(charsOf("\\.\\-\\/\\[\\]\\(\\)\\{\\}\\*\\+\\?\\|\\^\\$\\\\"), [
      ".-.",
      "---",
      "/-/",
      "[-[",
      "]-]",
      "(-(",
      ")-)",
      "{-{",
      "}-}",
      "*-*",
      "+-+",
      "?-?",
      "|-|",
      "^-^",
      "$-$",
      "\\-\\",
    ]);
  });

  it("parses escaped quotes, hash and other punctuation as literals", () => {
    assert.deepEqual(charsOf("\\\"\\'\\#\\=\\:\\,\\@\\%\\&\\~\\<\\>\\!\\;\\`"), [
      '"-"',
      "'-'",
      "#-#",
      "=-=",
      ":-:",
      ",-,",
      "@-@",
      "%-%",
      "&-&",
      "~-~",
      "<-<",
      ">->",
      "!-!",
      ";-;",
      "`-`",
    ]);
  });

  it("parses control escapes and hex escapes", () => {
    const nodes = items(parse("\\t\\n\\r\\f\\v\\x60\\x{41}"));
    assert.deepEqual(
      nodes.map((node) => setOf(node)),
      [[[9, 9]], [[10, 10]], [[13, 13]], [[12, 12]], [[11, 11]], [[0x60, 0x60]], [[0x41, 0x41]]],
    );
  });

  it("refuses unknown escapes, backreferences and broken hex escapes", () => {
    for (const bad of [
      "\\q",
      "\\1",
      "\\k<name>",
      "\\x6",
      "\\x{}",
      "\\x{110000}",
      "\\xZZ",
      "\\",
      "\\p{L}",
      "\\Q.\\E",
      "\\C",
    ]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });
});

describe("shorthand classes", () => {
  it("\\d and \\w are ASCII only", () => {
    const [d, w] = items(parse("\\d\\w")).map(setOf);
    assert.ok(d !== undefined && w !== undefined);
    assert.equal(contains(d, code("7")), true);
    assert.equal(contains(d, 0x0661), false); // Arabic-Indic digit one
    assert.equal(contains(w, code("_")), true);
    assert.equal(contains(w, code("Z")), true);
    assert.equal(contains(w, code("\u00e9")), false);
  });

  it("\\s includes Unicode spaces such as the no-break space", () => {
    const s = setOf(only(parse("\\s")));
    for (const unit of [9, 10, 11, 12, 13, 32, 0xa0, 0x2028, 0x3000, 0xfeff]) {
      assert.equal(contains(s, unit), true, unit.toString(16));
    }
    assert.equal(contains(s, code("a")), false);
    assert.equal(contains(s, 0x200b), false); // zero-width space is not white space
  });

  it("\\D, \\W and \\S are the complements", () => {
    const [d, w, s] = items(parse("\\D\\W\\S")).map(setOf);
    assert.ok(d !== undefined && w !== undefined && s !== undefined);
    assert.equal(contains(d, code("7")), false);
    assert.equal(contains(d, code("a")), true);
    assert.equal(contains(w, code("a")), false);
    assert.equal(contains(w, code("-")), true);
    assert.equal(contains(s, code(" ")), false);
    assert.equal(contains(s, code("x")), true);
  });

  it(". matches anything but a line feed, and anything with (?s)", () => {
    const dot = setOf(only(parse(".")));
    assert.equal(contains(dot, 10), false);
    assert.equal(contains(dot, 13), true);
    assert.equal(contains(dot, 0x2028), true);
    const dotAll = setOf(only(parse("(?s).")));
    assert.equal(contains(dotAll, 10), true);
    const scoped = items(parse("(?s:.).")).map((node) =>
      node.kind === "group" ? setOf(only(node.node)) : setOf(node),
    );
    assert.equal(contains(scoped[0] ?? [], 10), true);
    assert.equal(contains(scoped[1] ?? [], 10), false);
    const off = only(parse("(?s)(?-s:.)"));
    assert.ok(off.kind === "group");
    assert.equal(contains(setOf(only(off.node)), 10), false);
  });
});

describe("character classes", () => {
  it("parses ranges, single characters and escapes inside a class", () => {
    const set = setOf(only(parse("[a-c_\\-.\\]\\\\0-9]")));
    for (const c of "abc_-.]\\05") {
      assert.equal(contains(set, code(c)), true, c);
    }
    assert.equal(contains(set, code("d")), false);
  });

  it("parses a negated class", () => {
    const set = setOf(only(parse("[^a-z]")));
    assert.equal(contains(set, code("a")), false);
    assert.equal(contains(set, code("A")), true);
    assert.equal(contains(set, 10), true);
  });

  it("takes a leading ] or a trailing - literally", () => {
    const set = setOf(only(parse("[]a-]")));
    for (const c of "]a-") {
      assert.equal(contains(set, code(c)), true, c);
    }
  });

  it("parses shorthand classes and hex escapes inside a class", () => {
    const set = setOf(only(parse("[\\w\\s\\x60\"']")));
    for (const c of "aZ_ `\"'") {
      assert.equal(contains(set, code(c)), true, c);
    }
    assert.equal(contains(set, code("-")), false);
  });

  it("parses POSIX classes", () => {
    const set = setOf(only(parse("[[:alnum:]_]")));
    for (const c of "aZ9_") {
      assert.equal(contains(set, code(c)), true, c);
    }
    assert.equal(contains(set, code("-")), false);
    const upper = setOf(only(parse("[[:upper:][:digit:]]")));
    assert.equal(contains(upper, code("A")), true);
    assert.equal(contains(upper, code("a")), false);
    assert.equal(contains(upper, code("5")), true);
    const more = setOf(only(parse("[[:alpha:][:lower:][:space:][:xdigit:][:punct:]]")));
    for (const c of "aZ \tF!") {
      assert.equal(contains(more, code(c)), true, c);
    }
  });

  it("refuses broken classes", () => {
    for (const bad of [
      "[a-",
      "[",
      "[z-a]",
      "[[:nope:]]",
      "[[:alpha]",
      "[[:]",
      "[\\d-z]",
      "[a-\\d]",
      "[]",
      "[^]",
    ]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });
});

describe("groups and alternation", () => {
  it("parses a capturing, a non-capturing and named groups", () => {
    const nodes = items(parse("(a)(?:b)(?P<one>c)(?<two>d)"));
    assert.deepEqual(
      nodes.map((node) => (node.kind === "group" ? [node.capture, node.name ?? null] : node.kind)),
      [
        [true, null],
        [false, null],
        [true, "one"],
        [true, "two"],
      ],
    );
  });

  it("numbers capturing groups from left to right, nested ones too", () => {
    const tree = parse("(a(b))(?:c)(d)");
    const indexes: number[] = [];
    const walk = (node: Node): void => {
      switch (node.kind) {
        case "group":
          if (node.capture) {
            indexes.push(node.index);
          }
          walk(node.node);
          break;
        case "seq":
          node.items.forEach(walk);
          break;
        case "alt":
          node.options.forEach(walk);
          break;
        case "repeat":
        case "look":
          walk(node.node);
          break;
        case "char":
        case "assert":
          break;
      }
    };
    walk(tree);
    assert.deepEqual(indexes, [1, 2, 3]);
  });

  it("parses alternation with empty options", () => {
    const tree = parse("a|b|");
    assert.ok(tree.kind === "alt");
    assert.equal(tree.options.length, 3);
    assert.deepEqual(tree.options[2], { kind: "seq", items: [] });
  });

  it("refuses a duplicate or a bad group name", () => {
    for (const bad of ["(?P<a>x)(?P<a>y)", "(?P<>x)", "(?P<1a>x)", "(?P<a-b>x)", "(?P<ab"]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });

  it("refuses unbalanced parentheses", () => {
    for (const bad of ["(a", "a)", "((a)", "(?:a"]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });

  it("refuses lookbehind, atomic groups, comments and unknown flags", () => {
    for (const bad of [
      "(?<=a)b",
      "(?<!a)b",
      "(?>a)",
      "(?#c)",
      "(?m)a",
      "(?x)a",
      "(?U)a",
      "(?i",
      "(?P=a)",
      "(?|a)",
      "(?)",
      "(?-)",
    ]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });
});

describe("case-insensitive parts", () => {
  it("(?i) at the start folds every letter", () => {
    const set = setOf(only(parse("(?i)k")));
    assert.equal(contains(set, code("k")), true);
    assert.equal(contains(set, code("K")), true);
    assert.equal(contains(set, 0x212a), false);
  });

  it("(?i:...) folds only inside the group", () => {
    const [group, after] = items(parse("(?i:a)b"));
    assert.ok(group?.kind === "group" && after !== undefined);
    assert.equal(contains(setOf(only(group.node)), code("A")), true);
    assert.equal(contains(setOf(after), code("B")), false);
  });

  it("(?-i:...) turns folding off inside a case-insensitive pattern", () => {
    const [group, after] = items(parse("(?i)(?-i:a)b"));
    assert.ok(group?.kind === "group" && after !== undefined);
    assert.equal(contains(setOf(only(group.node)), code("A")), false);
    assert.equal(contains(setOf(after), code("B")), true);
  });

  it("(?-i) in the middle turns folding off for the rest", () => {
    const [first, second] = items(parse("(?i)a(?-i)b"));
    assert.ok(first !== undefined && second !== undefined);
    assert.equal(contains(setOf(first), code("A")), true);
    assert.equal(contains(setOf(second), code("B")), false);
  });

  it("a flag group in the middle changes the rest of its group", () => {
    const [first, second] = items(parse("a(?i)b"));
    assert.ok(first !== undefined && second !== undefined);
    assert.equal(contains(setOf(first), code("A")), false);
    assert.equal(contains(setOf(second), code("B")), true);
  });

  it("folds classes and negated classes", () => {
    const set = setOf(only(parse("(?i)[a-c]")));
    assert.equal(contains(set, code("B")), true);
    const negated = setOf(only(parse("(?i)[^a]")));
    assert.equal(contains(negated, code("A")), false);
    assert.equal(contains(negated, code("b")), true);
  });
});

describe("quantifiers", () => {
  const repeatOf = (pattern: string): { min: number; max: number | null; lazy: boolean } => {
    const node = only(parse(pattern));
    if (node.kind !== "repeat") {
      throw new Error(`expected a repeat, got ${node.kind}`);
    }
    return { min: node.min, max: node.max, lazy: node.lazy };
  };

  it("parses ?, *, + and their lazy forms", () => {
    assert.deepEqual(repeatOf("a?"), { min: 0, max: 1, lazy: false });
    assert.deepEqual(repeatOf("a*"), { min: 0, max: null, lazy: false });
    assert.deepEqual(repeatOf("a+"), { min: 1, max: null, lazy: false });
    assert.deepEqual(repeatOf("a??"), { min: 0, max: 1, lazy: true });
    assert.deepEqual(repeatOf("a*?"), { min: 0, max: null, lazy: true });
    assert.deepEqual(repeatOf("a+?"), { min: 1, max: null, lazy: true });
  });

  it("parses {n}, {n,}, {n,m} and lazy forms", () => {
    assert.deepEqual(repeatOf("a{3}"), { min: 3, max: 3, lazy: false });
    assert.deepEqual(repeatOf("a{3,}"), { min: 3, max: null, lazy: false });
    assert.deepEqual(repeatOf("a{0,50}"), { min: 0, max: 50, lazy: false });
    assert.deepEqual(repeatOf("a{0,50}?"), { min: 0, max: 50, lazy: true });
  });

  it("repeats a group and a class", () => {
    const node = only(parse("(?:ab){2}"));
    assert.equal(node.kind, "repeat");
    const cls = only(parse("[a-z]{4}"));
    assert.equal(cls.kind, "repeat");
  });

  it("takes a brace that is not a quantifier literally, like RE2", () => {
    assert.deepEqual(charsOf("a{"), ["a-a", "{-{"]);
    assert.deepEqual(charsOf("a{,3}"), ["a-a", "{-{", ",-,", "3-3", "}-}"]);
    assert.deepEqual(charsOf("{x}"), ["{-{", "x-x", "}-}"]);
  });

  it("refuses a quantifier with nothing to repeat, a double quantifier and m > n", () => {
    for (const bad of ["*a", "+", "?", "a**", "a{2}{3}", "a{5,2}", "(?:)*", "^*", "\\b+", "a|*b", "(*)"]) {
      assert.throws(() => parse(bad), PatternError, bad);
    }
  });

  it("refuses repeat counts above 100000", () => {
    assert.throws(() => parse("a{100001}"), PatternError);
    assert.throws(() => parse("a{1,100001}"), PatternError);
    assert.doesNotThrow(() => parse("a{1,100000}"));
  });
});

describe("anchors, boundaries and lookahead", () => {
  it("parses ^, $, \\A, \\z, \\b and \\B", () => {
    const nodes = items(parse("^\\A\\b\\B$\\z"));
    assert.deepEqual(
      nodes.map((node) => (node.kind === "assert" ? node.what : node.kind)),
      ["start", "start", "wordBoundary", "notWordBoundary", "end", "end"],
    );
  });

  it("parses a positive and a negative lookahead", () => {
    const [look, neg] = items(parse("(?=a)(?![a-z]|$)"));
    assert.ok(look?.kind === "look" && neg?.kind === "look");
    assert.equal(look.negative, false);
    assert.equal(neg.negative, true);
  });

  it("does not count lookahead groups as captures", () => {
    const tree = parse("(?![a-z])(b)");
    const group = items(tree)[1];
    assert.ok(group?.kind === "group" && group.capture);
    assert.equal(group.index, 1);
  });

  it("refuses a capture inside a lookahead", () => {
    assert.throws(() => parse("(?=(a))"), PatternError);
  });
});

describe("errors", () => {
  it("say where the problem is, never more than the pattern itself", () => {
    try {
      parse("abc\\q");
      assert.fail("should throw");
    } catch (error) {
      assert.ok(error instanceof PatternError);
      assert.equal(error.position, 3);
      assert.match(error.message, /at 3/);
    }
  });

  it("refuses an empty pattern and a pattern longer than 10000 characters", () => {
    assert.throws(() => parse(""), PatternError);
    assert.throws(() => parse("a".repeat(10_001)), PatternError);
    assert.doesNotThrow(() => parse("a".repeat(10_000)));
  });
});
