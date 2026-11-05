// Scenarios: a character set is a sorted list of UTF-16 code unit ranges.
// - a set built from single characters and ranges is normalized: sorted,
//   overlapping and touching ranges merged;
// - negation covers every code unit not in the set;
// - union and intersection behave like set algebra;
// - ASCII case folding adds the other case of every ASCII letter, and
//   nothing else (no Unicode folding, by design);
// - size counts code units; contains answers for one code unit.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  charSet,
  contains,
  foldAsciiCase,
  intersects,
  negate,
  size,
  union,
  type CharSet,
} from "../../src/pattern/charset.ts";

const code = (c: string): number => c.charCodeAt(0);

describe("charSet", () => {
  it("merges overlapping and touching ranges and sorts them", () => {
    const set = charSet([
      [code("x"), code("z")],
      [code("a"), code("c")],
      [code("b"), code("e")],
      [code("f"), code("f")],
    ]);
    assert.deepEqual(set, [
      [code("a"), code("f")],
      [code("x"), code("z")],
    ]);
  });

  it("drops an empty input to an empty set", () => {
    assert.deepEqual(charSet([]), []);
  });

  it("refuses a reversed range", () => {
    assert.throws(() => charSet([[code("z"), code("a")]]), /reversed range/);
  });

  it("refuses a code unit outside 0..0xFFFF", () => {
    assert.throws(() => charSet([[0, 0x10000]]), /code unit/);
    assert.throws(() => charSet([[-1, 3]]), /code unit/);
  });
});

describe("negate", () => {
  it("covers everything outside the set", () => {
    const set = charSet([[code("b"), code("d")]]);
    assert.deepEqual(negate(set), [
      [0, code("a")],
      [code("e"), 0xffff],
    ]);
  });

  it("of the empty set is every code unit, and back", () => {
    const all: CharSet = negate([]);
    assert.deepEqual(all, [[0, 0xffff]]);
    assert.deepEqual(negate(all), []);
  });

  it("keeps a set that touches both ends correct", () => {
    const set = charSet([
      [0, 9],
      [0xfff0, 0xffff],
    ]);
    assert.deepEqual(negate(set), [[10, 0xffef]]);
  });
});

describe("union and intersects", () => {
  it("unites two sets", () => {
    const a = charSet([[code("a"), code("c")]]);
    const b = charSet([[code("d"), code("f")]]);
    assert.deepEqual(union(a, b), [[code("a"), code("f")]]);
  });

  it("finds an intersection only when one exists", () => {
    const letters = charSet([[code("a"), code("z")]]);
    const digits = charSet([[code("0"), code("9")]]);
    const hex = charSet([
      [code("0"), code("9")],
      [code("a"), code("f")],
    ]);
    assert.equal(intersects(letters, digits), false);
    assert.equal(intersects(letters, hex), true);
    assert.equal(intersects(digits, hex), true);
    assert.equal(intersects([], hex), false);
  });

  it("sees an intersection of single points at range edges", () => {
    assert.equal(intersects([[5, 5]], [[5, 9]]), true);
    assert.equal(intersects([[1, 4]], [[5, 9]]), false);
    assert.equal(intersects([[10, 12]], [[5, 9]]), false);
  });
});

describe("foldAsciiCase", () => {
  it("adds the other case of ASCII letters", () => {
    const set = foldAsciiCase(charSet([[code("a"), code("c")]]));
    assert.deepEqual(set, [
      [code("A"), code("C")],
      [code("a"), code("c")],
    ]);
  });

  it("folds part of a range that crosses letter borders", () => {
    // "X" to "c" contains X Y Z [ \ ] ^ _ ` a b c
    const set = foldAsciiCase(charSet([[code("X"), code("c")]]));
    assert.equal(contains(set, code("x")), true);
    assert.equal(contains(set, code("C")), true);
    assert.equal(contains(set, code("d")), false);
  });

  it("leaves digits, symbols and non-ASCII letters alone", () => {
    const set = charSet([
      [code("0"), code("9")],
      [code("\u00e9"), code("\u00e9")],
      [code("K"), code("K")],
    ]);
    const folded = foldAsciiCase(set);
    assert.equal(contains(folded, code("k")), true);
    assert.equal(contains(folded, code("\u00c9")), false);
    // The Kelvin sign is not added for "k" (no Unicode folding).
    assert.equal(contains(folded, 0x212a), false);
    assert.equal(size(folded), size(set) + 1);
  });
});

describe("size and contains", () => {
  it("counts code units", () => {
    assert.equal(size(charSet([[0, 9]])), 10);
    assert.equal(size([]), 0);
  });

  it("answers membership at the edges", () => {
    const set = charSet([[10, 20]]);
    assert.equal(contains(set, 9), false);
    assert.equal(contains(set, 10), true);
    assert.equal(contains(set, 20), true);
    assert.equal(contains(set, 21), false);
  });
});
