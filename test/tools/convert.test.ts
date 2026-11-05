// Scenarios: converting gitleaks patterns keeps their meaning.
// - the optional left context [\w.-]{0,50}? is dropped, with or without (?i);
// - +, * and {n,} outside classes get an upper bound; lazy marks stay;
// - characters inside classes and escaped characters are never touched.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { boundRepeats, stripLeadingContext } from "../../tools/gitleaks/convert.ts";

describe("stripLeadingContext", () => {
  it("drops the left context with and without (?i)", () => {
    assert.equal(stripLeadingContext("(?i)[\\w.-]{0,50}?(?:key)x"), "(?i)(?:key)x");
    assert.equal(stripLeadingContext("[\\w.-]{0,50}?(?:key)x"), "(?:key)x");
    assert.equal(stripLeadingContext("\\bkey"), "\\bkey");
  });
});

describe("boundRepeats", () => {
  it("bounds +, * and {n,}", () => {
    assert.equal(boundRepeats("a+b*c{3,}", 9), "a{1,9}b{0,9}c{3,9}");
    assert.equal(boundRepeats("a+?b*?", 9), "a{1,9}?b{0,9}?");
  });

  it("leaves bounded repeats, classes and escapes alone", () => {
    assert.equal(boundRepeats("a{2,5}[+*]\\+\\*[a+]", 9), "a{2,5}[+*]\\+\\*[a+]");
    assert.equal(boundRepeats("[]+*][^]*]x+", 9), "[]+*][^]*]x{1,9}");
    assert.equal(boundRepeats("[[:alpha:]+]+", 9), "[[:alpha:]+]{1,9}");
    assert.equal(boundRepeats("\\x{41}+", 9), "\\x{41}{1,9}");
  });
});
