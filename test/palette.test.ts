import { describe, it, expect } from 'vitest';
import {
  byteColor,
  contrastRatio,
  GRID_GAP_DARK,
  GRID_GAP_LIGHT,
} from '../src/palette.ts';

const parse = (css: string): [number, number, number] => {
  const m = css.match(/\d+/g);
  if (!m || m.length < 3) throw new Error(`not an rgb() colour: ${css}`);
  return [Number(m[0]), Number(m[1]), Number(m[2])];
};

/**
 * The byte grid is a graphical object the exhibit depends on, so WCAG 2.1 SC
 * 1.4.11 applies: 3:1 against the colours adjacent to it. Adjacent is the 2px
 * `gap` in `.byte-grid`, showing `.xor-viz`'s background — near-black in both
 * themes, but not the SAME near-black, and the cell colour is an inline style
 * that cannot vary by theme. So every one of the 256 possible cells is checked
 * against both.
 *
 * Neither axe nor the gate's arithmetic contrast walk can see this: both
 * measure text against its backdrop, and these cells hold no text. This test is
 * the only thing standing between the palette and a silent regression.
 */
describe('byte-cell palette', () => {
  const all = Array.from({ length: 256 }, (_, b) => ({ b, rgb: parse(byteColor(b)) }));

  it('every byte value clears 3:1 against the dark-theme grid gap', () => {
    const bad = all
      .filter(({ rgb }) => contrastRatio(rgb, GRID_GAP_DARK) < 3)
      .map(({ b, rgb }) => `0x${b.toString(16)} rgb(${rgb}) ${contrastRatio(rgb, GRID_GAP_DARK).toFixed(2)}:1`);
    expect(bad).toEqual([]);
  });

  it('every byte value clears 3:1 against the light-theme grid gap', () => {
    const bad = all
      .filter(({ rgb }) => contrastRatio(rgb, GRID_GAP_LIGHT) < 3)
      .map(({ b, rgb }) => `0x${b.toString(16)} rgb(${rgb}) ${contrastRatio(rgb, GRID_GAP_LIGHT).toFixed(2)}:1`);
    expect(bad).toEqual([]);
  });

  it('stays injective, so identical colours still mean identical bytes', () => {
    // The exhibit's claim is that identical bytes look identical AND that
    // different bytes look different. Lifting a colour to clear the floor must
    // not collapse two values onto one.
    const seen = new Map<string, number>();
    const collisions: string[] = [];
    for (const { b, rgb } of all) {
      const key = rgb.join(',');
      const prev = seen.get(key);
      if (prev !== undefined) collisions.push(`0x${prev.toString(16)} and 0x${b.toString(16)} both rgb(${key})`);
      seen.set(key, b);
    }
    expect(collisions).toEqual([]);
  });

  it('is a pure function of the byte', () => {
    expect(byteColor(0x5a)).toBe(byteColor(0x5a));
  });
});
