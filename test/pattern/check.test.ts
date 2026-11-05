// Scenarios: the safety check is what lets keysnitch use the fast built-in
// RegExp engine on untrusted text. A rule passes only if its matching work
// per start position has a small, known upper bound.
// - every repeat has an upper bound, and that bound is at most 4096;
// - a repeat that can run more than once may only contain a body of fixed
//   length (no nested variable repeats, no variable alternation), which
//   rules out the classic exponential cases like (a+)+ and (a|aa)*;
// - a lookahead holds only single characters or the end of text;
// - a rule that can match empty text is refused;
// - a cost estimate adds the steps of every part, plus, for each chain of
//   neighbours that can trade characters, the product of the number of
//   lengths each can take; a rule above the limit is refused;
// - the check reports every problem, not just the first one.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { check, MAX_COST, MAX_REPEAT } from "../../src/pattern/check.ts";
import { parse } from "../../src/pattern/parse.ts";

const problems = (pattern: string): readonly string[] => check(parse(pattern)).problems;
const cost = (pattern: string): number => check(parse(pattern)).cost;

describe("safe rules pass", () => {
  for (const pattern of [
    "ghp_[A-Za-z0-9]{36}",
    "\\bATATT3[A-Za-z0-9_=-]{100,400}(?![A-Za-z0-9_=-])",
    "(?i)(?:api|app)[_-]?key[ \\t]{0,5}[:=][ \\t]{0,5}[\"']?([A-Za-z0-9]{16,64})",
    "xox[abposr]-[A-Za-z0-9-]{10,200}",
    "(?:[a-f0-9]{8}-){3}[a-f0-9]{12}",
    "AKIA[0-9A-Z]{16}",
    "a|bc|def",
    "^x$",
  ]) {
    it(pattern, () => {
      assert.deepEqual(problems(pattern), []);
    });
  }
});

describe("unbounded and huge repeats", () => {
  it("refuses *, + and {n,}", () => {
    for (const pattern of ["a*b", "ab+", "a{3,}b"]) {
      assert.ok(
        problems(pattern).some((p) => p.includes("no upper bound")),
        pattern,
      );
    }
  });

  it("refuses an upper bound above the limit and accepts the limit itself", () => {
    assert.ok(problems(`a{1,${String(MAX_REPEAT + 1)}}`).some((p) => p.includes("above")));
    assert.ok(!problems(`a{1,${String(MAX_REPEAT)}}`).some((p) => p.includes("above")));
  });
});

describe("nested repeats", () => {
  it("refuses the classic exponential shapes", () => {
    for (const pattern of [
      "(a+)+",
      "(?:a{1,5}){1,5}",
      "(?:a|aa){1,9}",
      "(?:[a-z]{2,3}-){2}",
      "(?:x(?:y)?){2}",
    ]) {
      assert.ok(
        problems(pattern).some((p) => p.includes("variable length")),
        pattern,
      );
    }
  });

  it("sees an unbounded part inside a repeated sequence or alternation", () => {
    for (const pattern of ["(?:ab*){2}", "(?:a|b*){2}"]) {
      assert.ok(
        problems(pattern).some((p) => p.includes("variable length")),
        pattern,
      );
    }
  });

  it("accepts an optional group with a variable body (it runs at most once)", () => {
    assert.deepEqual(problems("x(?:-[a-z]{2,6})?"), []);
  });

  it("accepts a repeated group of fixed length", () => {
    assert.deepEqual(problems("(?:[0-9a-f]{4}-){4}"), []);
    assert.deepEqual(problems("(?:ab|cd){3}"), []);
  });
});

describe("lookahead", () => {
  it("accepts single characters, classes and the end of text", () => {
    assert.deepEqual(problems("a(?![A-Za-z0-9])"), []);
    assert.deepEqual(problems("a(?=[\\s;]|$)"), []);
    assert.deepEqual(problems("a(?=b|c)"), []);
  });

  it("refuses anything longer or repeated inside a lookahead", () => {
    for (const pattern of ["a(?=bc)", "a(?![a-z]{2})", "a(?=(?:b))", "a(?=\\bb)", "a(?=^)"]) {
      assert.ok(
        problems(pattern).some((p) => p.includes("lookahead")),
        pattern,
      );
    }
  });
});

describe("empty matches", () => {
  it("refuses a rule that can match empty text", () => {
    for (const pattern of ["a?", "(?:a|)", "a{0,3}", "\\b", "^", "(?=a)", "(?:x?y?)"]) {
      assert.ok(
        problems(pattern).some((p) => p.includes("empty")),
        pattern,
      );
    }
  });
});

describe("cost", () => {
  it("is the number of steps for fixed text and for disjoint neighbours", () => {
    assert.equal(cost("abc"), 3);
    // [a-z]{1,10} then a digit: the letters cannot be given to the digit.
    assert.equal(cost("[a-z]{1,10}[0-9]"), 11);
  });

  it("adds the product of possible lengths of neighbours that can trade characters", () => {
    // Both parts take letters, so a run of letters can be split 10 x 10 ways.
    assert.equal(cost("[a-z]{1,10}[a-z]{1,10}"), 20 + 10 * 10);
  });

  it("carries the product through an optional part in the middle", () => {
    // The dash is optional, so the two letter runs still meet.
    assert.equal(cost("[a-z]{0,5}-?[a-z]{0,5}"), 14 + 6 * 2 * 6);
  });

  it("stops the chain at an optional part when the next part cannot share characters with it", () => {
    // "=" can go to the first part or the second, but digits belong only to the third.
    assert.equal(cost("[=a]{1,4}=?[0-9]{1,9}"), 15 + 4 * 2);
  });

  it("counts an unbounded part as MAX_REPEAT lengths", () => {
    assert.equal(cost("[a-z]{2,}[a-z]"), MAX_REPEAT - 1 + 1 + (MAX_REPEAT + 1) * 1);
  });

  it("looks through a word boundary into an alternation for shared characters", () => {
    // [a-z]{1,3} can end with "x", and the alternation can start with "x".
    assert.equal(cost("[a-z]{1,3}\\b(?:x|9)"), 6 + 3 * 1 * 1);
  });

  it("counts an alternation by its possible lengths in a chain, not by its size", () => {
    // Four keywords of four different lengths can end in four places.
    const keywords = "(?:jfrog|artifactory|bintray|xray)";
    assert.equal(cost(`${keywords}[a-z]{0,9}`), 27 + 10 + 8 * 10);
  });

  it("adds the options of an alternation", () => {
    assert.equal(cost("ab|cd"), 4);
  });

  it("counts a repeated fixed group by its runs", () => {
    assert.equal(cost("(?:ab){1,4}"), 2 * 4);
  });

  it("refuses a rule above the limit", () => {
    const pattern = "[a-z]{0,40}[a-z]{0,40}[a-z]{0,40}[a-z]{0,40}x";
    assert.ok(cost(pattern) > MAX_COST);
    assert.ok(problems(pattern).some((p) => p.includes("backtracking")));
  });
});

describe("reporting", () => {
  it("lists every problem", () => {
    const list = problems("(a+)+|b*");
    assert.ok(list.length >= 3, list.join("; "));
  });
});
