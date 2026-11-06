// Scenarios: readCode() splits TypeScript source into what runs and what
// does not, so the repository tests can check the code itself:
// - comments and the inside of strings and templates are blanked out;
// - code inside a template's ${...} stays code;
// - a slash starts a regex literal where an expression can begin
//   (after "=", "(", ",", "return" and the like), and is a division
//   after a name, a number, ")" or "]";
// - a slash inside a character class does not end a regex literal;
// - lengths and line numbers are kept, so a message can point at a line.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readCode } from "./code.ts";

describe("readCode", () => {
  it("blanks comments and keeps their length", () => {
    const source = "a = 1; // RegExp(x)\n/* eval( */ b = 2;";
    const { code } = readCode(source);
    assert.equal(code.length, source.length);
    assert.ok(!code.includes("RegExp"));
    assert.ok(!code.includes("eval"));
    assert.ok(code.includes("b = 2;"));
    assert.equal(code.split("\n").length, 2);
  });

  it("blanks the inside of strings, with escaped quotes", () => {
    const { code, regexes } = readCode(`const a = "x as any \\" /b/"; const b = 'it\\'s /c/';`);
    assert.ok(!code.includes("any"));
    assert.deepEqual(regexes, []);
    assert.ok(code.includes("const b ="));
  });

  it("blanks template text but keeps the code in ${...}", () => {
    const { code, regexes } = readCode("const a = `any /x/ ${f(/y+/g, { b: 1 })} any`;");
    assert.ok(!code.includes("any"));
    assert.ok(code.includes("f("));
    assert.deepEqual(regexes, ["/y+/g"]);
  });

  it("finds regex literals where an expression can begin", () => {
    for (const source of [
      "x = /a/;",
      "f(/a/)",
      "[1, /a/]",
      "return /a/.test(s);",
      "a && /a/.test(s)",
      "!/a/.test(s)",
      "{ k: /a/ }",
      "/a/.exec(s)",
    ]) {
      assert.deepEqual(readCode(source).regexes, ["/a/"], source);
    }
  });

  it("reads a division after a name, a number, ) or ]", () => {
    for (const source of ["a / b / c", "1 / 2 / 3", "(a) / 2 / x", "xs[0] / 2 / y", "a /= 2; b /= 3"]) {
      assert.deepEqual(readCode(source).regexes, [], source);
    }
  });

  it("keeps a slash in a class and an escaped slash inside the regex", () => {
    assert.deepEqual(readCode("x = /[/]a\\/b/giu; y = 1;").regexes, ["/[/]a\\/b/giu"]);
  });

  it("does not take a comment for a regex", () => {
    assert.deepEqual(readCode("x = 1; // a /b/\ny = 2; /* /c/ */").regexes, []);
  });
});
