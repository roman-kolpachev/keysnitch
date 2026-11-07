// Scenarios: the weekly gitleaks update (.github/workflows/gitleaks-update.yml).
// - it takes the newest gitleaks release that is at least 14 days old, the
//   same cooldown as Dependabot here; drafts and pre-releases never count;
// - nothing is newer than the version in use: no update;
// - the pull request says which rules were added and removed, which rules
//   failed the safety check, and whether `npm run check` passed;
// - what comes from the network is checked before it is written: the tag is
//   vX.Y.Z and nothing else (it goes into $GITHUB_OUTPUT, where a line break
//   would add outputs), the config is under 1 MB and holds gitleaks rules.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  checkedConfig,
  checkedTag,
  pickRelease,
  pullRequestBody,
  ruleChanges,
} from "../../tools/gitleaks/update.ts";

const now = new Date("2026-12-01T00:00:00Z");
const release = (
  tag: string,
  date: string,
  extra: Partial<{ draft: boolean; prerelease: boolean }> = {},
) => ({
  tag_name: tag,
  published_at: date,
  draft: extra.draft ?? false,
  prerelease: extra.prerelease ?? false,
});

describe("pickRelease", () => {
  it("takes the newest release older than 14 days", () => {
    const releases = [
      release("v8.32.0", "2026-11-25T00:00:00Z"),
      release("v8.31.0", "2026-11-10T00:00:00Z"),
      release("v8.30.1", "2026-03-21T00:00:00Z"),
    ];
    assert.equal(pickRelease(releases, "v8.30.1", now), "v8.31.0");
  });

  it("skips drafts and pre-releases", () => {
    const releases = [
      release("v9.0.0-rc1", "2026-10-01T00:00:00Z", { prerelease: true }),
      release("v8.31.0", "2026-10-01T00:00:00Z", { draft: true }),
      release("v8.30.1", "2026-03-21T00:00:00Z"),
    ];
    assert.equal(pickRelease(releases, "v8.30.1", now), undefined);
  });

  it("returns nothing when the version in use is the newest one old enough", () => {
    assert.equal(pickRelease([release("v8.30.1", "2026-03-21T00:00:00Z")], "v8.30.1", now), undefined);
    assert.equal(pickRelease([release("v8.30.2", "2026-11-28T00:00:00Z")], "v8.30.1", now), undefined);
  });
});

describe("ruleChanges", () => {
  it("lists added and removed rule ids, sorted", () => {
    assert.deepEqual(ruleChanges(["b", "a", "c"], ["c", "d", "a"]), { added: ["d"], removed: ["b"] });
  });
});

describe("pullRequestBody", () => {
  it("says what changed, what failed and that CI was started", () => {
    const body = pullRequestBody({
      tag: "v8.31.0",
      added: ["acme-api-key"],
      removed: [],
      failing: ["acme-api-key: unsafe pattern"],
      check: "fail",
    });
    assert.match(body, /gitleaks v8\.31\.0/u);
    assert.match(body, /acme-api-key/u);
    assert.match(body, /unsafe pattern/u);
    assert.match(body, /npm run check.*failed/iu);
    assert.match(body, /started CI and CodeQL on this branch/iu);
    assert.doesNotMatch(body, /close and reopen/iu);
  });
});

describe("what comes from the network", () => {
  it("takes a tag only in the form vX.Y.Z", () => {
    assert.equal(checkedTag("v8.31.0"), "v8.31.0");
    for (const bad of ["v8.31.0\nexit=1", "8.31.0", "v8.31", "v8.31.0-rc1", "../v8.31.0", ""]) {
      assert.throws(() => checkedTag(bad), /not a gitleaks release tag/u, JSON.stringify(bad));
    }
  });

  it("takes a config only when it is small and holds gitleaks rules", () => {
    const current = readFileSync(
      new URL("../../third_party/gitleaks/gitleaks.toml", import.meta.url),
      "utf8",
    );
    assert.equal(checkedConfig(current), current);
    assert.throws(() => checkedConfig(""), /no gitleaks rules/u);
    assert.throws(() => checkedConfig("<html>Not Found</html>"), /no gitleaks rules|cannot be read/u);
    assert.throws(() => checkedConfig(`${current}\n# ${"x".repeat(1_000_000)}\n`), /larger than 1 MB/u);
  });
});
