// Scenarios: properties of scan() over thousands of random texts (fast-check).
// - it never throws, whatever the text, including lone surrogates and
//   control characters;
// - findings are sorted, never overlap, never empty and stay inside the text;
// - the same text always gives the same findings;
// - a key put anywhere between words is found, and its finding is exactly
//   the key: no character before or after it.
// Values are built from parts here; none is a real credential.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { scan } from "#src/scan.ts";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const anyText = fc.string({ unit: "binary", maxLength: 600 });
const words = fc.array(fc.stringMatching(/^[a-z]{1,9}$/u), { maxLength: 30 });
const keyBody = fc.string({ unit: fc.constantFrom(...ALNUM.split("")), minLength: 36, maxLength: 36 });

describe("scan over random text", () => {
  it("never throws", () => {
    fc.assert(
      fc.property(anyText, (text) => {
        scan(text);
      }),
    );
  });

  it("returns sorted, separate, non-empty findings inside the text", () => {
    fc.assert(
      fc.property(anyText, (text) => {
        let previousEnd = 0;
        for (const finding of scan(text).findings) {
          assert.ok(finding.start >= previousEnd, "findings overlap or are out of order");
          assert.ok(finding.end > finding.start, "empty finding");
          assert.ok(finding.end <= text.length, "finding past the end of the text");
          previousEnd = finding.end;
        }
      }),
    );
  });

  it("gives the same findings for the same text", () => {
    fc.assert(
      fc.property(anyText, (text) => {
        assert.deepEqual(scan(text).findings, scan(text).findings);
      }),
    );
  });

  it("finds a key anywhere between words, exactly", () => {
    fc.assert(
      fc.property(words, words, keyBody, (before, after, body) => {
        const key = "gh" + "p_" + body;
        const prefix = before.length > 0 ? `${before.join(" ")} ` : "";
        const text = `${prefix}${key}${after.length > 0 ? ` ${after.join(" ")}` : ""}`;
        const hit = scan(text).findings.find((f) => text.slice(f.start, f.end).includes(key));
        assert.ok(hit !== undefined, text);
        assert.equal(text.slice(hit.start, hit.end), key);
      }),
    );
  });
});
