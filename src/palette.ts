/**
 * Cell colours for the XOR byte grids.
 *
 * The grid is the lab's central "aha": each square is one real byte, its colour
 * a deterministic function of the byte value, so identical bytes look identical
 * and a learner literally watches M become V. That only works if you can see
 * the square.
 *
 * WCAG 2.1 SC 1.4.11 asks for 3:1 between a graphical object and the colours
 * adjacent to it. Adjacent here is the 2px `gap` in `.byte-grid`, through which
 * `.xor-viz`'s own background shows: #050508 in the dark theme, #1a1a28 in the
 * light one. A cell darker than that gap is not a dim square, it is no square —
 * the grid loses its rows and columns.
 *
 * The original `hsl(hue 70% 32-80%)` band left 18% of the cells (dark) and 22%
 * (light) under 3:1 against that gap, worst case rgb(84,24,139) for 0xc0 at
 * 1.82:1 / 1.54:1. Raising the whole band instead would have cost the palette
 * its range: the blue-violet hues need L≈55% before they clear, which drags
 * every red and yellow into pastel. So the band is kept and a floor is applied
 * per colour — only the cells that need lifting are lifted.
 *
 * The colour is still a pure function of the byte, and still injective over all
 * 256 values (asserted in `test/palette.test.ts`), so nothing the exhibit
 * claims about it changes.
 */

/** sRGB relative luminance, WCAG 2.x definition. */
export function relativeLuminance([r, g, b]: [number, number, number]): number {
  const f = (v: number): number => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

/** WCAG contrast ratio between two opaque sRGB colours. */
export function contrastRatio(
  a: [number, number, number],
  b: [number, number, number]
): number {
  const [hi, lo] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** The two backgrounds the grid gap can show. */
export const GRID_GAP_DARK: [number, number, number] = [5, 5, 8]; // #050508
export const GRID_GAP_LIGHT: [number, number, number] = [26, 26, 40]; // #1a1a28

/**
 * Luminance a cell must reach to clear 3:1 against the LIGHTER of the two gap
 * colours. The cell colour is an inline style and therefore theme-independent,
 * so it has to satisfy both themes, and #1a1a28 is the harder one:
 * 3 * (0.01112 + 0.05) - 0.05 = 0.13335. Rounded up to 0.137 for a little
 * headroom, which lands the worst cell at 3.06:1 rather than exactly 3.00:1.
 */
const MIN_CELL_LUMINANCE = 0.137;

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hp = (((h % 360) + 360) % 360) / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  const [r1, g1, b1] =
    hp < 1 ? [c, x, 0] :
    hp < 2 ? [x, c, 0] :
    hp < 3 ? [0, c, x] :
    hp < 4 ? [0, x, c] :
    hp < 5 ? [x, 0, c] :
             [c, 0, x];
  const m = l - c / 2;
  return [
    Math.round((r1 + m) * 255),
    Math.round((g1 + m) * 255),
    Math.round((b1 + m) * 255),
  ];
}

/**
 * Deterministic colour for a byte value.
 *
 * Hue carries the value; lightness varies on a second, shorter cycle so that
 * neighbouring values are told apart by more than hue alone. Lightness is then
 * raised — one percentage point at a time, hue and saturation untouched — until
 * the colour clears `MIN_CELL_LUMINANCE`.
 */
export function byteColor(b: number): string {
  // 360/256, not 360/255: dividing by 255 sends 0x00 to hue 0 and 0xff to hue
  // 360, which is the SAME hue. That was survivable while lightness alone told
  // them apart (32% vs 47%), but both of those sit under the luminance floor in
  // the red band, so both get lifted to the same lightness and the two bytes
  // collide outright. `test/palette.test.ts` caught it.
  const hue = (b * 360) / 256;
  let light = 32 + (b % 48); // 32-80% — keeps every cell visibly distinct
  let rgb = hslToRgb(hue, 0.7, light / 100);
  while (relativeLuminance(rgb) < MIN_CELL_LUMINANCE && light < 100) {
    light += 1;
    rgb = hslToRgb(hue, 0.7, light / 100);
  }
  return `rgb(${rgb[0]} ${rgb[1]} ${rgb[2]})`;
}
