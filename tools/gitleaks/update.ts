// The weekly gitleaks update (.github/workflows/gitleaks-update.yml).
// Usage: node tools/gitleaks/update.ts fetch
//          picks the newest gitleaks release at least 14 days old; when it is
//          newer than third_party/gitleaks/VERSION, downloads its config,
//          writes VERSION, keeps the current rule ids in rules-before.json and
//          prints tag=<tag> to $GITHUB_OUTPUT
//        node tools/gitleaks/update.ts summary <tag> <pass|fail>
//          prints the pull request body (reads rules-before.json and
//          import-report.txt)

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { parseGitleaksToml } from "./toml.ts";

export interface Release {
  readonly tag_name: string;
  readonly published_at: string;
  readonly draft: boolean;
  readonly prerelease: boolean;
}

/** Same cooldown as Dependabot here: a release must be two weeks old. */
const MIN_AGE_DAYS = 14;

function versionOf(tag: string): readonly number[] | undefined {
  const match = /^v(\d+)\.(\d+)\.(\d+)$/u.exec(tag);
  return match === null ? undefined : [Number(match[1]), Number(match[2]), Number(match[3])];
}

function isNewer(tag: string, than: string): boolean {
  const a = versionOf(tag);
  const b = versionOf(than);
  if (a === undefined || b === undefined) {
    return false;
  }
  for (let i = 0; i < 3; i += 1) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) {
      return (a[i] ?? 0) > (b[i] ?? 0);
    }
  }
  return false;
}

/**
 * A release tag goes into $GITHUB_OUTPUT and VERSION: vX.Y.Z and nothing else.
 * The tag written is built again from its three numbers, not the text the
 * network sent.
 */
export function checkedTag(tag: string): string {
  const version = versionOf(tag);
  if (version === undefined) {
    throw new Error(`${JSON.stringify(tag)} is not a gitleaks release tag`);
  }
  return `v${version.map(String).join(".")}`;
}

/** The gitleaks config today is about 100 KB. */
const MAX_CONFIG_LENGTH = 1_000_000;

/** The downloaded config is written only when it is small and holds gitleaks rules. */
export function checkedConfig(text: string): string {
  if (text.length > MAX_CONFIG_LENGTH) {
    throw new Error("the gitleaks config is larger than 1 MB");
  }
  let count: number;
  try {
    count = parseGitleaksToml(text).length;
  } catch (error) {
    throw new Error(
      `the gitleaks config cannot be read: ${error instanceof Error ? error.message : "unknown error"}`,
      { cause: error },
    );
  }
  if (count === 0) {
    throw new Error("the gitleaks config has no gitleaks rules");
  }
  return text;
}

/** The newest stable release old enough and newer than the one in use, if any. */
export function pickRelease(releases: readonly Release[], current: string, now: Date): string | undefined {
  const cutoff = now.getTime() - MIN_AGE_DAYS * 24 * 60 * 60 * 1000;
  const eligible = releases.filter(
    (r) =>
      !r.draft &&
      !r.prerelease &&
      versionOf(r.tag_name) !== undefined &&
      Date.parse(r.published_at) <= cutoff,
  );
  const newest = eligible.reduce<string | undefined>(
    (best, r) => (best === undefined || isNewer(r.tag_name, best) ? r.tag_name : best),
    undefined,
  );
  return newest !== undefined && isNewer(newest, current) ? newest : undefined;
}

export function ruleChanges(
  before: readonly string[],
  after: readonly string[],
): { added: string[]; removed: string[] } {
  return {
    added: after.filter((id) => !before.includes(id)).sort(),
    removed: before.filter((id) => !after.includes(id)).sort(),
  };
}

export function pullRequestBody(update: {
  readonly tag: string;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  readonly failing: readonly string[];
  readonly check: string;
}): string {
  const list = (items: readonly string[]): string =>
    items.length === 0 ? "none" : items.map((item) => `\`${item}\``).join(", ");
  return [
    `gitleaks ${update.tag}: its config in third_party/gitleaks and the rules regenerated from it.`,
    "",
    `- Rules added: ${list(update.added)}`,
    `- Rules removed: ${list(update.removed)}`,
    `- Rules that fail the safety check: ${update.failing.length === 0 ? "none" : ""}`,
    ...update.failing.map((line) => `  - ${line}`),
    `- \`npm run check\` ${update.check === "pass" ? "passed" : "failed: see the workflow run; a failing rule needs an entry in tools/gitleaks/overrides.ts"}`,
    "",
    "Opened by the weekly workflow, which also started CI and CodeQL on this branch: GitHub runs no workflow on pull requests its own token opens, but it runs workflows started by hand. Their checks show below.",
    "",
  ].join("\n");
}

const root = new URL("../../", import.meta.url);

async function ruleIds(): Promise<string[]> {
  const module: unknown = await import(
    `${new URL("src/rules/gitleaks.ts", root).href}?t=${String(Date.now())}`
  );
  if (typeof module !== "object" || module === null || !("gitleaksRules" in module)) {
    throw new Error("src/rules/gitleaks.ts has no gitleaksRules");
  }
  const rules: unknown = module.gitleaksRules;
  if (!Array.isArray(rules)) {
    throw new Error("gitleaksRules is not a list");
  }
  return rules.flatMap((rule: unknown) =>
    typeof rule === "object" && rule !== null && "id" in rule && typeof rule.id === "string" ? [rule.id] : [],
  );
}

function isRelease(value: unknown): value is Release {
  return (
    typeof value === "object" &&
    value !== null &&
    "tag_name" in value &&
    typeof value.tag_name === "string" &&
    "published_at" in value &&
    typeof value.published_at === "string" &&
    "draft" in value &&
    typeof value.draft === "boolean" &&
    "prerelease" in value &&
    typeof value.prerelease === "boolean"
  );
}

async function fetchUpdate(): Promise<void> {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json" };
  const token = process.env["GH_TOKEN"];
  if (token !== undefined && token !== "") {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const response = await fetch("https://api.github.com/repos/gitleaks/gitleaks/releases?per_page=30", {
    headers,
  });
  if (!response.ok) {
    throw new Error(`GitHub API answered ${String(response.status)}`);
  }
  const body: unknown = await response.json();
  const releases = Array.isArray(body) ? body.filter(isRelease) : [];
  const current = readFileSync(new URL("third_party/gitleaks/VERSION", root), "utf8").trim();
  const picked = pickRelease(releases, current, new Date());
  if (picked === undefined) {
    process.stdout.write(`gitleaks ${current} is current\n`);
    return;
  }
  const tag = checkedTag(picked);
  const config = await fetch(
    `https://raw.githubusercontent.com/gitleaks/gitleaks/${tag}/config/gitleaks.toml`,
  );
  if (!config.ok) {
    throw new Error(`gitleaks.toml of ${tag}: ${String(config.status)}`);
  }
  const text = checkedConfig(await config.text());
  writeFileSync(new URL("rules-before.json", root), JSON.stringify(await ruleIds()));
  writeFileSync(new URL("third_party/gitleaks/gitleaks.toml", root), text);
  writeFileSync(new URL("third_party/gitleaks/VERSION", root), `${tag}\n`);
  const output = process.env["GITHUB_OUTPUT"];
  if (output !== undefined && output !== "") {
    appendFileSync(output, `tag=${tag}\n`);
  }
  process.stdout.write(`gitleaks ${current} -> ${tag}\n`);
}

async function summary(tag: string, check: string): Promise<void> {
  const before: unknown = JSON.parse(readFileSync(new URL("rules-before.json", root), "utf8"));
  const beforeIds = Array.isArray(before)
    ? before.filter((id: unknown): id is string => typeof id === "string")
    : [];
  const reportPath = new URL("import-report.txt", root);
  const failing = existsSync(reportPath)
    ? readFileSync(reportPath, "utf8")
        .split("\n")
        .filter((line) => line !== "" && !line.startsWith("skipped ") && !/^\d+ converted/u.test(line))
    : [];
  const changes = ruleChanges(beforeIds, await ruleIds());
  process.stdout.write(pullRequestBody({ tag, ...changes, failing, check }));
}

if (
  import.meta.url === new URL(process.argv[1] ?? "", "file:").href ||
  process.argv[1]?.endsWith("update.ts") === true
) {
  const [mode, tag, check] = process.argv.slice(2);
  if (mode === "fetch") {
    await fetchUpdate();
  } else if (mode === "summary" && tag !== undefined && check !== undefined) {
    await summary(tag, check);
  }
}
