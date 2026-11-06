// Prints the uncovered branches and lines of an lcov file, so a missing
// test is easy to find. Usage: node tools/uncovered.ts coverage/lcov.info
import { readFileSync } from "node:fs";

const file = process.argv[2] ?? "coverage/lcov.info";
let current = "";
for (const line of readFileSync(file, "utf8").split("\n")) {
  if (line.startsWith("SF:")) current = line.slice(3);
  else if (line.startsWith("BRDA:") && line.endsWith(",0"))
    process.stdout.write(`${current}:${line.slice(5).split(",")[0] ?? ""} branch\n`);
  else if (line.startsWith("DA:") && line.endsWith(",0"))
    process.stdout.write(`${current}:${line.slice(3).split(",")[0] ?? ""} line\n`);
}
