import { describe, expect, it } from 'vitest';
import { init } from 'z3-solver';
// import { Rbac, hasSeparationOfDutyConflict } from './rbac';

// --- Sanity check: confirms the z3-solver WASM toolchain is wired up. ---
// Safe to delete once you trust the setup; keep the pattern for later specs
// that need the solver.
describe('z3-solver toolchain', () => {
  it('initializes and solves a trivial constraint', async () => {
    const { Context } = await init();
    const { Solver, Int } = Context('main');
    const solver = new Solver();
    const x = Int.const('x');
    solver.add(x.gt(0), x.lt(10));
    expect(await solver.check()).toBe('sat');
  });
  
  it('initializes and solves a less trivial constraint', async () => {
    const { Context } = await init();
    const { Solver, Int } = Context('main');
    const solver = new Solver();
    const x = Int.const('x');
    const y = Int.const('y');
    solver.add(x.gt(0), x.lt(10));
    solver.add(y.gt(42), y.lt(51));
    solver.add(x.mul(y).eq(300));
    await solver.check();
    expect(await solver.check()).toBe('sat');

    const model = solver.model();
    const xVal = model.eval(x);
    const yVal = model.eval(y);
    console.log(`${xVal}, ${yVal}`);
  });
});