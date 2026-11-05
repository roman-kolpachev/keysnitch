// Scenarios: Shannon entropy in bits per character, used by rules with a
// minimum entropy to skip values like "aaaaaaaa".
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { entropy } from "../src/entropy.ts";

describe("entropy", () => {
  it("is 0 for empty text and for one repeated character", () => {
    assert.equal(entropy(""), 0);
    assert.equal(entropy("aaaa"), 0);
  });

  it("is log2 of the alphabet size for evenly used characters", () => {
    assert.equal(entropy("ab"), 1);
    assert.equal(entropy("abcd"), 2);
    assert.equal(entropy("0123456789abcdef"), 4);
  });

  it("counts UTF-16 code units", () => {
    assert.equal(entropy("éé"), 0);
  });
});
