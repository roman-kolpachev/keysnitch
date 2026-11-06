// TypeScript rewrites ".ts" imports to ".js" in the built JavaScript but
// not in the .d.ts files. Consumers would then look for ./scan.ts next to
// dist/scan.d.ts. This step rewrites the declaration imports after the build.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dist = new URL("../dist", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/u, "$1");

function walk(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

let changed = 0;
for (const path of walk(dist).filter((file) => file.endsWith(".d.ts"))) {
  const text = readFileSync(path, "utf8");
  const fixed = text.replace(/(from\s+["']\.{1,2}\/[^"']+)\.ts(["'])/gu, "$1.js$2");
  if (fixed !== text) {
    writeFileSync(path, fixed);
    changed += 1;
  }
}
process.stdout.write(`fixed imports in ${String(changed)} declaration files\n`);
