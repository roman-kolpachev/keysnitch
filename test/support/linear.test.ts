// Scenarios: the timing check of the rules tells a slow machine from a slow rule.
// - a run inside the budget passes at once, nothing else is measured;
// - one slow run passes when the next one is inside the budget;
// - a machine that stays slow passes while twice the text takes twice the time;
// - time that grows with the square of the text fails, also when the machine
//   slows some of the runs;
// - time that grows faster than that fails;
// - a rule over the ceiling fails even when it is linear.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BUDGET_MS, CEILING_MS, SLOW_INPUT, slowness } from "./linear.ts";

/** A clock for a rule with this cost at SLOW_INPUT; `noise` multiplies each run in turn. */
function clock(ms: number, power: number, noise: readonly number[] = [1]) {
  const sizes: number[] = [];
  const time = (size: number): number => {
    const factor = noise[sizes.length % noise.length] ?? 1;
    sizes.push(size);
    return ms * (size / SLOW_INPUT) ** power * factor;
  };
  return { sizes, time };
}

describe("slowness", () => {
  it("passes a run inside the budget and measures nothing else", () => {
    const { sizes, time } = clock(BUDGET_MS - 1, 2);
    assert.equal(slowness(time), undefined);
    assert.deepEqual(sizes, [SLOW_INPUT]);
  });

  it("passes when only one run was slow", () => {
    const { time } = clock(270, 1, [2, 2, 1, 1]);
    assert.equal(slowness(time), undefined);
  });

  it("passes a linear rule on a machine that stays slow", () => {
    assert.equal(slowness(clock(401, 1).time), undefined);
    assert.equal(slowness(clock(1000, 1).time), undefined);
    assert.equal(slowness(clock(600, 1, [1.4, 1, 1, 1.3, 1.2]).time), undefined);
  });

  it("fails time that grows with the square of the text", () => {
    assert.match(String(slowness(clock(BUDGET_MS, 2).time)), /4\.0 times/u);
    assert.match(String(slowness(clock(1000, 2).time)), /4\.0 times/u);
  });

  it("fails it also when the machine slows some of the runs", () => {
    assert.match(String(slowness(clock(600, 2, [1.6, 1, 1, 1.2, 1.3]).time)), /times/u);
    assert.match(String(slowness(clock(600, 2, [1.6, 1, 1.5, 1, 1, 1.1]).time)), /times/u);
  });

  it("fails time that grows faster than that", () => {
    assert.match(String(slowness(clock(500, 3).time)), /8\.0 times/u);
  });

  it("fails a linear rule over the ceiling", () => {
    assert.match(String(slowness(clock(CEILING_MS, 1).time)), /2000 ms/u);
  });
});
