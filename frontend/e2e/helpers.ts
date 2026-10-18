import { type Page, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

export const SHOTS = process.env.CAPTURE_SCREENSHOTS ? path.resolve(process.cwd(), '../docs/screenshots') : null;

export async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.waitForTimeout(450); // let transitions settle
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`) });
}

export async function replayT(page: Page): Promise<number> {
  return Number(await page.getByTestId('frame-debug').getAttribute('data-t'));
}

export async function currentEventId(page: Page): Promise<string> {
  return (await page.getByTestId('frame-debug').getAttribute('data-current')) ?? '';
}

/** Seek the replay by driving the timeline range input like a user drag. */
export async function seek(page: Page, t: number) {
  await page.getByTestId('timeline-scrubber').evaluate((el, value) => {
    const input = el as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    setter.call(input, String(value));
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, t);
  const max = Number(await page.getByTestId('timeline-scrubber').getAttribute('max'));
  await expect.poll(() => replayT(page)).toBeCloseTo(Math.min(t, max), 0);
}

/** Replay offset (seconds) of the first event of a type, from the event feed order. */
export async function eventOffset(page: Page, title: string): Promise<number> {
  const item = page.getByTestId('event-feed').locator('button', { hasText: title }).first();
  const text = await item.locator('.br-feed-time').innerText();
  const [m, s] = text.split(':').map(Number);
  return m * 60 + s + 1.2;
}

export async function noHorizontalScroll(page: Page) {
  const [scrollWidth, innerWidth] = await page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
  expect(scrollWidth).toBeLessThanOrEqual(innerWidth);
}
