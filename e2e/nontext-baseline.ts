/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND IT IS MEANT TO STAY THAT WAY. It was captured with six
 * entries — the five `.tab-btn`s at 1.40:1 (dark) / 2.05:1 (light) and
 * `#cl-theme-toggle` at 2.45:1 — and all six were fixed rather than accepted.
 * Three further findings this oracle cannot reach were hand-measured off
 * screenshots and fixed alongside them: the two `<a class="cl-btn">` topbar
 * controls (the CONTROL selector list matches no anchors), the protocol
 * diagram's five `.actor-box` strokes at 1.31:1, and the XOR grid's byte cells,
 * 18-22% of which sat under 3:1 against the 2px gap between them.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
