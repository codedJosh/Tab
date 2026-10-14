import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

function luminance(hex) {
  const channels = hex.match(/[a-f\d]{2}/gi).map((part) => parseInt(part, 16) / 255);
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(foreground, background) {
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

test('muted text meets AA contrast against the site’s light surface colors', () => {
  const css = readFileSync(new URL('../frontend/styles.css', import.meta.url), 'utf8');
  const muted = css.match(/--muted:\s*(#[\da-f]{6})/i)?.[1];
  assert.ok(muted, 'the global muted text token exists');
  for (const background of ['#ffffff', '#f3f5f3', '#e7ece8']) {
    assert.ok(contrast(muted, background) >= 4.5, `${muted} on ${background} has sufficient contrast`);
  }
});
