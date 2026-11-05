/** Shannon entropy of a string in bits per UTF-16 code unit. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    counts.set(unit, (counts.get(unit) ?? 0) + 1);
  }
  let bits = 0;
  for (const count of counts.values()) {
    const share = count / value.length;
    bits -= share * Math.log2(share);
  }
  return bits;
}
