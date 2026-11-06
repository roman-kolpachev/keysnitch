// Scenarios: after "name:", a value is reported only if it does not read
// like a word, a brand or an address, because people write
// "Credentials: GitHub" and "Docs: id.atlassian.com" in prose.
// - 20 characters or more: random enough;
// - a digit together with letters: random (hunter2, Q8w2Er4T);
// - a strong symbol together with letters: random (P@ssword, abc(1)xyz);
// - words, brand names (GitHub, DigitalOcean) and addresses
//   (id.atlassian.com, npmjs.com) are not.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { looksRandom } from "#src/rules/keysnitch.ts";

describe("looksRandom", () => {
  it("accepts long values", () => {
    assert.equal(looksRandom("correcthorsebatterystaple"), true);
  });

  it("accepts digits with letters and strong symbols with letters", () => {
    for (const value of ["hunter2", "Q8w2Er4Ty6Ui", "P@ssword", "abc(1)xyz", "s3cr3t-value", "Welcome!"]) {
      assert.equal(looksRandom(value), true, value);
    }
  });

  it("refuses words, brand names, addresses and digits alone", () => {
    for (const value of [
      "deactivate",
      "GitHub",
      "DigitalOcean",
      "id.atlassian.com",
      "npmjs.com",
      "pypi.org",
      "123456",
      "------",
    ]) {
      assert.equal(looksRandom(value), false, value);
    }
  });
});
