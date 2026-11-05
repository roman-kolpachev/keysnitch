// Scenarios: compile() is the only way a rule becomes a RegExp.
// - it refuses a pattern that fails the safety check, and says why;
// - the RegExp it builds behaves like the rule says: case folding,
//   "." without line feeds, \s with Unicode spaces, word boundaries,
//   anchors, lookahead, lazy and greedy repeats;
// - special characters are escaped, so a literal "$" or "]" stays literal;
// - capture groups keep their numbers and names;
// - the RegExp has no shared state: two scans at once get the same answers.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compile, UnsafePatternError } from "../../src/pattern/compile.ts";
import { emit } from "../../src/pattern/emit.ts";
import { parse, PatternError } from "../../src/pattern/parse.ts";

function matches(pattern: string, text: string): string[] {
  return [...text.matchAll(compile(pattern).regex)].map((match) => match[0]);
}

describe("refusals", () => {
  it("refuses an unsafe pattern and lists the problems", () => {
    assert.throws(
      () => compile("(a+)+"),
      (error: unknown) => {
        assert.ok(error instanceof UnsafePatternError);
        assert.ok(error.problems.length >= 2);
        assert.match(error.message, /unsafe pattern/);
        return true;
      },
    );
  });

  it("passes on a syntax error as a PatternError", () => {
    assert.throws(() => compile("a\\q"), PatternError);
  });
});

describe("behaviour of the built RegExp", () => {
  it("folds case only where the rule says", () => {
    assert.deepEqual(matches("(?i)ab", "AB ab aB"), ["AB", "ab", "aB"]);
    assert.deepEqual(matches("(?i:a)b", "Ab AB ab"), ["Ab", "ab"]);
  });

  it("keeps . away from line feeds unless (?s)", () => {
    assert.deepEqual(matches("a.b", "a\nb a\rb"), ["a\rb"]);
    assert.deepEqual(matches("(?s)a.b", "a\nb"), ["a\nb"]);
  });

  it("treats a no-break space as white space", () => {
    assert.deepEqual(matches("=\\s[a-z]{3}", "=\u00a0abc"), ["=\u00a0abc"]);
  });

  it("anchors to the whole text, not to lines", () => {
    assert.deepEqual(matches("^ab", "ab\nab"), ["ab"]);
    assert.deepEqual(matches("ab$", "ab\nab"), ["ab"]);
  });

  it("respects word boundaries and lookahead", () => {
    assert.deepEqual(matches("\\bkey[0-9]{2}\\b", "key12 xkey34 key56x key78"), ["key12", "key78"]);
    assert.deepEqual(matches("tok-[a-z]{2,4}(?![a-z0-9])", "tok-abcd tok-abcde tok-ab1"), ["tok-abcd"]);
    assert.deepEqual(matches("k[0-9](?=;|$)", "k1; k2, k3"), ["k1", "k3"]);
  });

  it("keeps a value that ends with a dash, unlike \\b", () => {
    assert.deepEqual(matches("sk-[A-Za-z0-9-]{4,8}(?![A-Za-z0-9-])", "sk-abc- "), ["sk-abc-"]);
  });

  it("repeats greedily and lazily as written", () => {
    assert.deepEqual(matches("a[0-9]{1,3}", "a12345"), ["a123"]);
    assert.deepEqual(matches("a[0-9]{1,3}?", "a12345"), ["a1"]);
    assert.deepEqual(matches("x(?:ab){2}", "xababab"), ["xabab"]);
    assert.deepEqual(matches("x(?:ab|cd)", "xcd"), ["xcd"]);
  });

  it("escapes every special character", () => {
    const list = ["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}", "/", "-"];
    const specials = list.join("");
    const pattern = list.map((c) => `\\${c}`).join("");
    assert.deepEqual(matches(pattern, `x${specials}x`), [specials]);
    assert.deepEqual(matches("[\\]\\-\\^\\\\a]{5}", "]-^\\a"), ["]-^\\a"]);
  });

  it("escapes control and non-ASCII characters", () => {
    assert.deepEqual(matches("\\t\\x00é", "\t\u0000é"), ["\t\u0000é"]);
    assert.deepEqual(matches("[\\x00-\\x1f]{2}", "a\u0001\u001fb"), ["\u0001\u001f"]);
  });

  it("matches any character for a negated empty set", () => {
    assert.deepEqual(matches("a(?s:.)b", "a\nb"), ["a\nb"]);
  });

  it("keeps capture numbers and names", () => {
    const { regex, groups } = compile("(?P<pre>[a-z]{2})-([0-9]{2})");
    const match = regex.exec("ab-12");
    assert.ok(match !== null);
    assert.equal(match[1], "ab");
    assert.equal(match[2], "12");
    assert.equal(match.groups?.["pre"], "ab");
    assert.equal(groups, 2);
    assert.deepEqual(match.indices?.[2], [3, 5]);
  });

  it("gives the same answers to two interleaved scans", () => {
    const { regex } = compile("[a-z]{2}");
    const one = "ab cd ef".matchAll(regex);
    const two = "gh ij".matchAll(regex);
    const results = [
      one.next().value?.[0],
      two.next().value?.[0],
      one.next().value?.[0],
      two.next().value?.[0],
    ];
    assert.deepEqual(results, ["ab", "gh", "cd", "ij"]);
  });
});

describe("emit", () => {
  it("writes a short negated class when that is shorter", () => {
    assert.equal(emit(parse("[^a]")), "[^a]");
    assert.equal(emit(parse("[a-c]")), "[a-c]");
  });

  it("wraps an alternation inside a sequence", () => {
    assert.equal(emit(parse("x(?:a|b)y")), "x(?:a|b)y");
    assert.equal(emit(parse("a|b")), "a|b");
  });

  it("writes repeats in a uniform way", () => {
    assert.equal(emit(parse("a?")), "a?");
    assert.equal(emit(parse("a{2}")), "a{2}");
    assert.equal(emit(parse("a{2,5}?")), "a{2,5}?");
    assert.equal(emit(parse("a*")), "a{0,}");
  });

  it("wraps a repeated sequence that is not a group", () => {
    // The parser never builds this, but emit must still be correct.
    assert.equal(emit({ kind: "repeat", min: 1, max: 2, lazy: false, node: parse("ab") }), "(?:ab){1,2}");
  });
});
