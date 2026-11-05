// Scenarios: promises about the repository itself, checked on every run.
// - no runtime dependencies; dev dependencies pinned to exact versions;
//   npm never runs install scripts; Node 24 or newer;
// - the TypeScript settings stay at their strictest;
// - source and test files hold only ASCII, so no invisible or look-alike
//   character can hide in the code (Trojan Source); other characters are
//   written as escapes;
// - src/ runs anywhere: no node: imports, no console, no eval, no network,
//   no process;
// - texts are written plainly, without long dashes;
// - keysnitch finds no credential in its own source, tools and docs;
// - the published package holds only dist and the documents.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scan } from "../src/scan.ts";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/u, "$1");
const read = (path: string): string => readFileSync(join(root, path), "utf8");

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function json(path: string): Record<string, unknown> {
  const value: unknown = JSON.parse(read(path));
  if (!isRecord(value)) throw new Error(`${path} is not an object`);
  return value;
}

function files(directory: string, extensions: readonly string[]): string[] {
  const out: string[] = [];
  const walk = (path: string): void => {
    for (const name of readdirSync(join(root, path))) {
      const child = join(path, name);
      if (statSync(join(root, child)).isDirectory()) walk(child);
      else if (extensions.some((extension) => name.endsWith(extension))) out.push(child);
    }
  };
  walk(directory);
  return out;
}

const packageJson = json("package.json");

describe("dependencies", () => {
  it("has no runtime dependencies", () => {
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies", "bundleDependencies"]) {
      assert.equal(packageJson[field], undefined, field);
    }
  });

  it("pins every dev dependency to an exact version", () => {
    const dev = packageJson["devDependencies"];
    assert.ok(isRecord(dev));
    for (const [name, version] of Object.entries(dev)) {
      assert.match(String(version), /^\d+\.\d+\.\d+$/u, name);
    }
  });

  it("has no install scripts and tells npm not to run any", () => {
    const scripts = packageJson["scripts"];
    assert.ok(isRecord(scripts));
    for (const hook of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) {
      assert.equal(scripts[hook], undefined, hook);
    }
    const npmrc = read(".npmrc");
    assert.match(npmrc, /^ignore-scripts=true$/mu);
    assert.match(npmrc, /^save-exact=true$/mu);
  });

  it("needs Node 24 or newer and has no side effects", () => {
    assert.deepEqual(packageJson["engines"], { node: ">=24" });
    assert.equal(packageJson["sideEffects"], false);
    assert.equal(packageJson["type"], "module");
  });

  it("publishes only the build and the documents", () => {
    assert.deepEqual(packageJson["files"], ["dist", "LICENSE", "NOTICE.md", "README.md", "CHANGELOG.md"]);
  });
});

describe("TypeScript settings", () => {
  it("keeps every strict option on", () => {
    const text = read("tsconfig.json").replace(/^\s*\/\/.*$/gmu, "");
    const config: unknown = JSON.parse(text);
    assert.ok(isRecord(config) && isRecord(config["compilerOptions"]));
    const options = config["compilerOptions"];
    for (const flag of [
      "strict",
      "noUncheckedIndexedAccess",
      "exactOptionalPropertyTypes",
      "noPropertyAccessFromIndexSignature",
      "noImplicitOverride",
      "noImplicitReturns",
      "noFallthroughCasesInSwitch",
      "noUnusedLocals",
      "noUnusedParameters",
      "useUnknownInCatchVariables",
      "verbatimModuleSyntax",
      "erasableSyntaxOnly",
    ]) {
      assert.equal(options[flag], true, flag);
    }
    assert.equal(options["skipLibCheck"], false);
  });
});

describe("source text", () => {
  const code = [
    ...files("src", [".ts"]),
    ...files("test", [".ts", ".json"]),
    ...files("tools", [".ts"]),
    ...files("bench", [".ts"]),
  ];

  it("is ASCII only, so nothing invisible can hide in it", () => {
    for (const path of code) {
      const text = read(path);
      for (let index = 0; index < text.length; index += 1) {
        const unit = text.charCodeAt(index);
        const allowed = unit === 0x0a || unit === 0x0d || unit === 0x09 || (unit >= 0x20 && unit <= 0x7e);
        if (!allowed)
          assert.fail(`${path}: character 0x${unit.toString(16)} at ${String(index)}; write it as an escape`);
      }
    }
  });

  it("keeps src free of Node, console, eval, network and process", () => {
    for (const path of files("src", [".ts"])) {
      const text = read(path);
      for (const banned of [
        'from "node:',
        "console.",
        "eval(",
        "new Function",
        "fetch(",
        "XMLHttpRequest",
        "process.",
        "require(",
      ]) {
        assert.ok(!text.includes(banned), `${path} uses ${banned}`);
      }
    }
  });

  it("has no long dashes in documents and code", () => {
    const documents = [
      ...files(".", [".md"]).filter(
        (path) => !path.startsWith("node_modules") && !path.startsWith("third_party"),
      ),
      ...code,
    ];
    for (const path of documents) {
      assert.ok(!read(path).includes("\u2014"), `${path} has a long dash`);
    }
  });
});

describe("no credentials in the repository", () => {
  it("finds nothing in src (outside the rule files), tools, bench and the documents", () => {
    // Rule files hold patterns and documented example values, not secrets.
    const paths = [
      ...files("src", [".ts"]).filter((path) => !path.replaceAll("\\", "/").startsWith("src/rules/")),
      ...files("tools", [".ts"]),
      ...files("bench", [".ts"]),
      ...files(".", [".md"]).filter((path) => !path.startsWith("node_modules")),
    ];
    for (const path of paths) {
      // "1Password" (the company name) after a colon looks like a password to
      // the setting rule; that is the price of finding "hunter2" in YAML.
      const findings = scan(read(path), { ignore: (value) => value === "1Password" }).findings;
      assert.deepEqual(
        findings.map((finding) => finding.ruleId),
        [],
        relative(root, join(root, path)),
      );
    }
  });
});
