import { describe, expect, it } from 'vitest';
import { escapeHtml } from '../src/escape.ts';

describe('escapeHtml', () => {
  it('escapes every character that can open a tag or end an attribute', () => {
    expect(escapeHtml('&')).toBe('&amp;');
    expect(escapeHtml('<')).toBe('&lt;');
    expect(escapeHtml('>')).toBe('&gt;');
    expect(escapeHtml('"')).toBe('&quot;');
    expect(escapeHtml("'")).toBe('&#39;');
  });

  it('escapes the ampersand first, so the other escapes survive', () => {
    expect(escapeHtml('<a>')).toBe('&lt;a&gt;');
    expect(escapeHtml('&lt;')).toBe('&amp;lt;');
  });

  it('leaves an exception message inert — the js/xss-through-exception shape', () => {
    // Seven catch handlers rendered `${e}` into markup. An Error whose message carries
    // a tag is what that cost, so this is the value they now pass through.
    const message = String(new Error('<img src=x onerror="document.title=\'xss\'">'));
    const escaped = escapeHtml(message);
    expect(escaped).not.toMatch(/[<>"']/);
    expect(escaped).toContain('img src=x onerror=');
    expect(escaped).toContain('&lt;img');
  });

  it('leaves an identity unable to close the attribute it is rendered into', () => {
    // The escrow explanation and several panels interpolate the typed identity into
    // an attribute, so a double quote is the character that matters there.
    const escaped = escapeHtml('alice@example.com" data-injected="yes');
    expect(escaped).not.toContain('"');
    expect(escaped).toBe('alice@example.com&quot; data-injected=&quot;yes');
  });
});
