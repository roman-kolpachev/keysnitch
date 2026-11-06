// Scenarios: mask() shows a little of a value so people can recognise it,
// never enough to use it.
// - 16 characters or more: the first 4 and the last 4;
// - 10 to 15 characters: the first 2 and the last 2;
// - shorter values: nothing at all;
// - never more than half of the value is shown;
// - the stars do not reveal the length.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mask } from "#src/mask.ts";

describe("mask", () => {
  it("shows 4 + 4 characters of a long value", () => {
    assert.equal(mask("ATATT3xFfGF0abcdefghij1234"), "ATAT****1234");
    assert.equal(mask("a".repeat(15) + "b"), "aaaa****aaab");
  });

  it("shows 2 + 2 characters of a medium value", () => {
    assert.equal(mask("abcdefghij"), "ab****ij");
    assert.equal(mask("abcdefghijklmno"), "ab****no");
  });

  it("shows nothing of a short value", () => {
    assert.equal(mask("abcdefghi"), "****");
    assert.equal(mask("a"), "****");
    assert.equal(mask(""), "****");
  });

  it("never shows more than half of the value", () => {
    for (let length = 0; length <= 64; length += 1) {
      const value = "x".repeat(length);
      const shown = mask(value).replace("****", "").length;
      assert.ok(shown * 2 <= length || shown === 0, String(length));
    }
  });

  it("does not split a surrogate pair at the edges", () => {
    // Four code units from each end would cut an emoji in half on both sides.
    const value = `abc\u{1F600}${"x".repeat(10)}\u{1F600}xyz`;
    const masked = mask(value);
    assert.doesNotThrow(() => encodeURIComponent(masked), masked);
    assert.equal(masked, "abc****xyz");
    // A whole emoji at the edge is kept whole.
    assert.equal(mask(`ab${"x".repeat(14)}\u{1F600}yz`), "abxx****\u{1F600}yz");
  });
});
