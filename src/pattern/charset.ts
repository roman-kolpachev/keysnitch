// A set of UTF-16 code units, kept as sorted, non-touching, inclusive
// ranges. Patterns work on code units (like a JavaScript RegExp without
// the `u` flag), which is enough for credentials: every known format is
// ASCII.

export type Range = readonly [low: number, high: number];
export type CharSet = readonly Range[];

const MAX = 0xffff;

function checkUnit(unit: number): void {
  if (!Number.isInteger(unit) || unit < 0 || unit > MAX) {
    throw new RangeError(`code unit out of range: ${String(unit)}`);
  }
}

/** Builds a normalized set: sorted, overlapping and touching ranges merged. */
export function charSet(ranges: readonly Range[]): CharSet {
  for (const [low, high] of ranges) {
    checkUnit(low);
    checkUnit(high);
    if (low > high) throw new RangeError("reversed range in a character set");
  }
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [low, high] of sorted) {
    const last = merged.at(-1);
    if (last !== undefined && low <= last[1] + 1) {
      last[1] = Math.max(last[1], high);
    } else {
      merged.push([low, high]);
    }
  }
  return merged;
}

/** Every code unit that is not in the set. */
export function negate(set: CharSet): CharSet {
  const result: Range[] = [];
  let next = 0;
  for (const [low, high] of set) {
    if (low > next) result.push([next, low - 1]);
    next = high + 1;
  }
  if (next <= MAX) result.push([next, MAX]);
  return result;
}

export function union(a: CharSet, b: CharSet): CharSet {
  return charSet([...a, ...b]);
}

export function intersects(a: CharSet, b: CharSet): boolean {
  // Sets in patterns hold a few ranges, so the simple pairwise check is fast.
  return a.some(([low, high]) => b.some(([from, to]) => low <= to && from <= high));
}

export function contains(set: CharSet, unit: number): boolean {
  return set.some(([low, high]) => unit >= low && unit <= high);
}

export function size(set: CharSet): number {
  return set.reduce((total, [low, high]) => total + high - low + 1, 0);
}

const UPPER_A = 0x41;
const UPPER_Z = 0x5a;
const LOWER_A = 0x61;
const LOWER_Z = 0x7a;
const CASE_GAP = LOWER_A - UPPER_A;

function overlap(range: Range, low: number, high: number): Range | undefined {
  const from = Math.max(range[0], low);
  const to = Math.min(range[1], high);
  return from <= to ? [from, to] : undefined;
}

/**
 * Adds the other case of every ASCII letter in the set. Only ASCII: the
 * Kelvin sign is not a "k" here, which keeps case-insensitive rules from
 * matching look-alike characters.
 */
export function foldAsciiCase(set: CharSet): CharSet {
  const extra: Range[] = [];
  for (const range of set) {
    const upper = overlap(range, UPPER_A, UPPER_Z);
    if (upper !== undefined) extra.push([upper[0] + CASE_GAP, upper[1] + CASE_GAP]);
    const lower = overlap(range, LOWER_A, LOWER_Z);
    if (lower !== undefined) extra.push([lower[0] - CASE_GAP, lower[1] - CASE_GAP]);
  }
  return union(set, extra);
}
