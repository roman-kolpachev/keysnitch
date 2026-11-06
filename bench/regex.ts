// Measures the built-in RegExp engine against re2js (a JavaScript port of
// RE2) on rule shapes, and keysnitch's whole scan on large texts. The
// numbers back docs/decisions.md D-2.
//
// re2js is not a dependency of keysnitch. To include it in the run:
//   npm install --no-save re2js@2.9.1 && node bench/regex.ts

import { scan } from "../src/index.ts";

// One GitHub-shaped token at the end, built here (no key-shaped text in the repository).
const fakeToken = ["ghp", "_", "Qw3rTy7Ui9Op1As2Df4Gh6", "Jk8Lz0XcVbNm12"].join("");
const text = `${"the quick brown fox jumps over the lazy dog issue PAY-17 deploy staging ".repeat(14_000)}${fakeToken} end`;

function time(run: () => void): number {
  run();
  const started = performance.now();
  for (let index = 0; index < 5; index += 1) {
    run();
  }
  return (performance.now() - started) / 5;
}

const shapes: readonly [string, string, string][] = [
  ["prefix rule", "ghp_[A-Za-z0-9]{36}", "g"],
  ["keyword rule", "(?:app_?key|secret|token)\\s*[:=]\\s*[A-Za-z0-9]{16,64}", "gi"],
  ["no prefix", "[A-Za-z0-9]{20}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}", "g"],
];

interface Re2 {
  readonly RE2JS: {
    readonly CASE_INSENSITIVE: number;
    compile(source: string, flags?: number): { matcher(input: string): { find(): boolean } };
  };
}

function isRe2(value: unknown): value is Re2 {
  return typeof value === "object" && value !== null && "RE2JS" in value;
}

let re2: Re2 | undefined;
try {
  // A variable name keeps TypeScript from looking for the package's types.
  const name = "re2js";
  const loaded: unknown = await import(name);
  if (isRe2(loaded)) {
    re2 = loaded;
  }
} catch {
  re2 = undefined;
}

const out: string[] = [`text: ${String(Math.round(text.length / 1024))} KB, Node ${process.version}`, ""];
out.push("| Shape | Built-in RegExp | re2js | Slower |", "| --- | ---: | ---: | ---: |");
for (const [name, source, flags] of shapes) {
  const native = new RegExp(source, flags);
  const nativeMs = time(() => {
    const count = [...text.matchAll(native)].length;
    if (count < 0) {
      throw new Error("unreachable");
    }
  });
  let re2Cell = "not installed";
  let ratio = "";
  if (re2 !== undefined) {
    const compiled = re2.RE2JS.compile(source, flags.includes("i") ? re2.RE2JS.CASE_INSENSITIVE : 0);
    const re2Ms = time(() => {
      const matcher = compiled.matcher(text);
      let found = 0;
      while (matcher.find()) {
        found += 1;
      }
      if (found < 0) {
        throw new Error("unreachable");
      }
    });
    re2Cell = `${re2Ms.toFixed(1)} ms`;
    ratio = `x${(re2Ms / nativeMs).toFixed(0)}`;
  }
  out.push(`| ${name} | ${nativeMs.toFixed(1)} ms | ${re2Cell} | ${ratio} |`);
}

out.push("", "| keysnitch scan, all built-in rules | Time |", "| --- | ---: |");
const keywordText = "token key secret api password auth basic bearer sk- xox ".repeat(18_000);
for (const [name, input] of [
  ["1 MB of prose", text],
  ["1 MB of rule keywords", keywordText],
] as const) {
  out.push(`| ${name} | ${time(() => scan(input)).toFixed(0)} ms |`);
}
process.stdout.write(`${out.join("\n")}\n`);
