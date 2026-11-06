const STARS = "****";

function isHighSurrogate(unit: number): boolean {
  return unit >= 0xd800 && unit <= 0xdbff;
}

function isLowSurrogate(unit: number): boolean {
  return unit >= 0xdc00 && unit <= 0xdfff;
}

/**
 * Hides a value but keeps a few characters to recognise it: 4 + 4 for 16
 * characters or more, 2 + 2 for 10 to 15, nothing below. Never more than
 * half of the value, and never half of an emoji.
 */
export function mask(value: string): string {
  const keep = value.length >= 16 ? 4 : value.length >= 10 ? 2 : 0;
  if (keep === 0) {
    return STARS;
  }
  const headEnd = isHighSurrogate(value.charCodeAt(keep - 1)) ? keep - 1 : keep;
  const tailStart = isLowSurrogate(value.charCodeAt(value.length - keep))
    ? value.length - keep + 1
    : value.length - keep;
  return `${value.slice(0, headEnd)}${STARS}${value.slice(tailStart)}`;
}
