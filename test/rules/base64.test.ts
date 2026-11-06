// Scenarios: the Basic header rule decodes Base64 itself (no atob, no
// Buffer: keysnitch runs anywhere) and reports only "user:secret".
// - padding with "==", "=" and none decodes like the standard;
// - a length that is not a multiple of 4, or a character outside the
//   alphabet, is not Base64;
// - decoded text with control or non-ASCII bytes is not a password header;
// - "user:secret" needs a user and a secret of 3 or more characters.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decodeBase64, isEncodedUserAndSecret } from "../../src/rules/keysnitch.ts";

const encode = (text: string): string => Buffer.from(text, "latin1").toString("base64");

describe("decodeBase64", () => {
  it("decodes with two, one and no padding characters", () => {
    for (const text of ["a", "ab", "abc", "abcd", "alice:wonderland12", "x:y+z/w"]) {
      assert.equal(decodeBase64(encode(text)), text, text);
    }
  });

  it("refuses a wrong length and characters outside the alphabet", () => {
    assert.equal(decodeBase64("YWJj Z"), undefined);
    assert.equal(decodeBase64("YWJ"), undefined);
    assert.equal(decodeBase64("YW-j"), undefined);
    assert.equal(decodeBase64("YW_j"), undefined);
  });
});

describe("isEncodedUserAndSecret", () => {
  it("accepts user:secret", () => {
    assert.equal(isEncodedUserAndSecret(encode("alice:wonderland12")), true);
    assert.equal(isEncodedUserAndSecret(encode("bot:abc")), true);
  });

  it("refuses text without a user, without a colon or with a short secret", () => {
    assert.equal(isEncodedUserAndSecret(encode(":wonderland")), false);
    assert.equal(isEncodedUserAndSecret(encode("hello world")), false);
    assert.equal(isEncodedUserAndSecret(encode("alice:ab")), false);
  });

  it("refuses control and non-ASCII bytes", () => {
    assert.equal(isEncodedUserAndSecret(encode("alice:wonder\u0001land")), false);
    assert.equal(isEncodedUserAndSecret(encode("alice:wonder\u00e9land")), false);
  });

  it("refuses values that are not Base64", () => {
    assert.equal(isEncodedUserAndSecret("not base64!"), false);
  });
});
