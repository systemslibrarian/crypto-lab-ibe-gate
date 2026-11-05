/**
 * The escape every value this lab renders goes through.
 *
 * It lived in main.ts, and two CodeQL alerts this round were about values that
 * reached markup WITHOUT it: js/xss-through-exception (seven catch handlers rendered
 * `${e}` raw, 47f90fd) and js/xss-through-dom (the escrow explanation embedded the
 * identity the visitor typed, 3d7ad72). Both fixes route through this function, so
 * what it covers is what they are worth.
 *
 * Extracted here so that is a property a test holds rather than a line in main.ts.
 * The order matters: `&` must go first, or it rewrites the entities the later
 * replacements introduce. Both quote characters are escaped because several call
 * sites interpolate into an attribute.
 */
export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
