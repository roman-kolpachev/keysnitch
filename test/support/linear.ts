// Tells a slow machine from a slow rule. A budget in milliseconds alone fails
// on a busy CI runner, so a scan over the budget must show how its time grows.

export const SLOW_INPUT = 100_000;
/** A scan of SLOW_INPUT characters inside this time passes at once. */
export const BUDGET_MS = 400;
/** However slow the machine, a scan of SLOW_INPUT characters must be faster. */
export const CEILING_MS = 2000;

const TRIES = 5;
/** Twice the text takes a linear scan 2 times as long and a quadratic one 4 times. */
const MAX_GROWTH = 3;

/**
 * Says why a scan is too slow, or undefined when it is not. `time` scans slow
 * input of the given size and returns the milliseconds it took.
 */
export function slowness(time: (size: number) => number): string | undefined {
  let once = Infinity;
  let twice = Infinity;
  for (let run = 0; run < TRIES; run += 1) {
    once = Math.min(once, time(SLOW_INPUT));
    if (once < BUDGET_MS) {
      return undefined;
    }
    twice = Math.min(twice, time(2 * SLOW_INPUT));
  }
  if (once >= CEILING_MS) {
    return `took ${once.toFixed(0)} ms for ${String(SLOW_INPUT)} characters`;
  }
  const growth = twice / once;
  return growth < MAX_GROWTH
    ? undefined
    : `took ${once.toFixed(0)} ms, and ${growth.toFixed(1)} times as long for twice the text`;
}
