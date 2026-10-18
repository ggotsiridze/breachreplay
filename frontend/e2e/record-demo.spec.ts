/**
 * Recruiter demo recording (not part of the normal E2E run).
 *   RECORD_DEMO=1 npx playwright test e2e/record-demo.spec.ts
 * Produces a video in test-results; scripts/make_demo_gif.sh turns it into docs/demo assets.
 */
import { expect, test } from '@playwright/test';

import { replayT } from './helpers';

test.skip(!process.env.RECORD_DEMO, 'set RECORD_DEMO=1 to record the demo video');
test.use({ viewport: { width: 1280, height: 720 }, video: { mode: 'on', size: { width: 1280, height: 720 } } });

test('record recruiter demo', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.waitForTimeout(2600);
  await page.getByTestId('watch-demo').hover();
  await page.waitForTimeout(500);
  await page.getByTestId('watch-demo').click();
  await expect(page.getByTestId('incident-view')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: '10x' }).click();
  const max = Number(await page.getByTestId('timeline-scrubber').getAttribute('max'));
  await expect.poll(() => replayT(page), { timeout: 60_000, intervals: [250] }).toBeGreaterThanOrEqual(max - 0.05);
  await page.waitForTimeout(1500);

  await page.getByTestId('node-asset-ws-03').click();
  await page.waitForTimeout(3200);
  await page.getByTestId('stop-the-breach').hover();
  await page.waitForTimeout(400);
  await page.getByTestId('stop-the-breach').click();
  await page.waitForTimeout(2000);
  await page.getByTestId('run-simulation').click();
  await expect.poll(() => replayT(page), { timeout: 60_000, intervals: [250] }).toBeGreaterThanOrEqual(max - 0.05);
  await page.waitForTimeout(3500);
});
