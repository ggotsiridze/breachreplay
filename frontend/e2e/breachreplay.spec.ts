import { expect, test } from '@playwright/test';

import { currentEventId, eventOffset, noHorizontalScroll, replayT, seek, shot } from './helpers';

test.describe('BreachReplay recruiter journey', () => {
  test('replay, investigate and contain the demo incident', async ({ page }) => {
    const fatal: string[] = [];
    page.on('pageerror', (e) => fatal.push(`pageerror: ${e.message}`));
    page.on('console', (m) => {
      if (m.type() === 'error') fatal.push(`console: ${m.text()}`);
    });

    // 1-2. Landing and branding
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'BREACHREPLAY' })).toBeVisible();
    await expect(page.getByText('Turn network evidence into an attack you can watch.')).toBeVisible();
    await noHorizontalScroll(page);
    await shot(page, '01-landing');

    // 3-5. Watch demo -> real analysis progress -> complete
    await page.getByTestId('watch-demo').click();
    await expect(page.getByTestId('analysis-progress')).toBeVisible();
    await expect(page.getByText('Demo incident · synthetic network traffic')).toBeVisible();
    await expect(page.getByTestId('step-2')).toHaveAttribute('data-status', /running|done/);
    await page.waitForTimeout(700);
    await shot(page, '02-analysis-progress');
    await expect(page.getByTestId('step-6')).toHaveAttribute('data-status', 'done', { timeout: 60_000 });

    // 6-7. Incident graph with the expected demo assets
    await expect(page.getByTestId('incident-view')).toBeVisible({ timeout: 30_000 });
    for (const id of ['asset-203-0-113-45', 'asset-web-01', 'asset-ws-03', 'asset-db-01']) {
      await expect(page.getByTestId(`node-${id}`)).toBeVisible();
    }
    await expect(page.getByTestId('source-chip')).toContainText(/synthetic network traffic/i);
    await expect(page.getByTestId('speed-badge')).toHaveText('5x REPLAY');

    // 8-9. Replay starts and the timeline advances
    const t0 = await replayT(page);
    await expect.poll(() => replayT(page), { timeout: 10_000 }).toBeGreaterThan(t0 + 2);

    // 10-12. Active event, active edge and node state change as the replay runs
    await expect.poll(() => currentEventId(page), { timeout: 20_000 }).not.toBe('');
    const firstEvent = await currentEventId(page);
    await expect(page.getByTestId('node-asset-web-01')).toHaveAttribute('data-state', 'AFFECTED', { timeout: 20_000 });
    await expect.poll(() => currentEventId(page), { timeout: 20_000 }).not.toBe(firstEvent);
    const activeEdges = page.locator('[data-testid^="edge-"][data-active="true"]');
    await expect(activeEdges.first()).toBeAttached();

    // 13. Pause works
    await page.getByTestId('play-toggle').click();
    await expect(page.getByTestId('play-toggle')).toHaveAttribute('aria-label', 'Play');
    const paused = await replayT(page);
    await page.waitForTimeout(1000);
    expect(await replayT(page)).toBeCloseTo(paused, 1);

    // 14. Scrub to the lateral movement: deterministic state at that moment
    const lateral = await eventOffset(page, 'Lateral movement');
    await seek(page, lateral);
    await expect(page.getByTestId('current-event')).toContainText('Lateral movement');
    await expect(page.getByTestId('current-event')).toContainText('T1021.002');
    await expect(page.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'AFFECTED');
    await expect(page.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'NORMAL');
    await expect(page.getByTestId('edge-edge-web-01--ws-03')).toHaveAttribute('data-active', 'true');
    await expect(page.getByTestId('phase-indicator')).toContainText('Lateral Movement');
    await shot(page, '04-lateral-movement');

    // Scrub to the crown-jewel moment
    const crown = await eventOffset(page, 'Crown jewel access');
    await seek(page, crown);
    await expect(page.getByTestId('crown-moment')).toBeVisible();
    await expect(page.getByTestId('crown-status')).toHaveText('YES');
    await expect(page.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'AFFECTED');
    await shot(page, '05-crown-jewel');

    // Scrub backwards: state is reconstructed, not accumulated
    await seek(page, 1);
    await expect(page.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'NORMAL');
    await expect(page.getByTestId('crown-status')).toHaveText('NO');

    // Full observed incident (hero view)
    await seek(page, 999);
    await expect(page.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'AFFECTED');
    await shot(page, '03-attack-graph');

    // 15. Speed change works
    await page.getByRole('button', { name: '10x' }).click();
    await expect(page.getByTestId('speed-badge')).toHaveText('10x REPLAY');
    await seek(page, 0);
    await page.getByTestId('play-toggle').click();
    await page.waitForTimeout(1500);
    expect(await replayT(page)).toBeGreaterThan(9);
    await page.getByTestId('play-toggle').click();

    // 16-18. Investigate an asset: evidence and ATT&CK
    await seek(page, 999);
    await page.getByTestId('node-asset-ws-03').click();
    const drawer = page.getByTestId('investigate-drawer');
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('heading', { name: 'WS-03' })).toBeVisible();
    await expect(drawer).toContainText(/high-confidence affected/i);
    await expect(drawer.getByTestId('mitre-mapping')).toContainText('T1021.002');
    await expect(drawer.getByTestId('reasons')).toContainText('Administrative share accessed');
    await expect(drawer.getByTestId('evidence-list')).toContainText('NTLM authentication as CORP-DEMO\\svc-demo');
    await expect(drawer.getByTestId('evidence-list')).toContainText('Suricata alert');
    await shot(page, '06-investigate');

    // 19-20. Contain mode with an isolate control
    await page.getByTestId('stop-the-breach').click();
    const panel = page.getByTestId('contain-panel');
    await expect(panel).toBeVisible();
    await expect(panel.getByTestId('control-isolate_asset').getByRole('checkbox')).toBeChecked();
    await expect(panel.getByLabel('Isolate asset target')).toHaveValue('asset-ws-03');
    await shot(page, '07-containment');

    // 21-24. Run the simulation: the path is interrupted and the crown jewel protected
    await panel.getByTestId('run-simulation').click();
    await expect(page.getByTestId('scenario-chip')).toContainText('Simulated outcome');
    await page.getByRole('button', { name: '5x' }).click();
    const interruption = lateral;
    await seek(page, interruption);
    await expect(page.getByTestId('edge-edge-web-01--ws-03')).toHaveAttribute('data-blocked', 'true');
    await expect(page.getByTestId('interrupt-moment')).toBeVisible();
    await expect(page.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'CONTAINED');
    await expect(page.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'PROTECTED');
    await shot(page, '08-interrupted-path');

    await seek(page, 999);
    await expect(page.getByTestId('crown-status')).toHaveText('PROTECTED');
    const compare = page.getByTestId('comparison-panel');
    await expect(compare).toBeVisible();
    await expect(compare).toContainText('Breach interrupted');
    await expect(compare.getByTestId('compare-crown-jewel-reached')).toHaveText('NO');
    await expect(compare.getByTestId('compare-observed-path')).toHaveText('INTERRUPTED');
    await compare.scrollIntoViewIfNeeded();
    await shot(page, '09-comparison');

    // Observed evidence is still available unchanged
    await page.getByRole('button', { name: 'Observed', exact: true }).click();
    await seek(page, 999);
    await expect(page.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'AFFECTED');

    // 25-26. No fatal console errors; no horizontal scrolling on a laptop viewport
    await noHorizontalScroll(page);
    await page.setViewportSize({ width: 1280, height: 800 });
    await noHorizontalScroll(page);
    expect(fatal).toEqual([]);
  });

  test('smaller viewport remains usable', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await expect(page.getByTestId('watch-demo')).toBeVisible();
    await noHorizontalScroll(page);
    await page.getByTestId('watch-demo').click();
    await expect(page.getByTestId('incident-view')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('node-asset-ws-03')).toBeVisible();
    await expect(page.getByTestId('play-toggle')).toBeVisible();
    await expect(page.getByTestId('stop-the-breach')).toBeVisible();
    await noHorizontalScroll(page);
    await page.getByTestId('stop-the-breach').click();
    await page.getByTestId('run-simulation').scrollIntoViewIfNeeded();
    await page.getByTestId('run-simulation').click();
    await expect(page.getByTestId('comparison-panel')).toBeVisible();
    await noHorizontalScroll(page);
    if (process.env.CAPTURE_SCREENSHOTS) await page.screenshot({ path: '../docs/screenshots/10-mobile.png' });
  });

  test('rejects an invalid upload with a professional error', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('file-input').setInputFiles({ name: 'evil.pcap', mimeType: 'application/octet-stream', buffer: Buffer.from('this is not a packet capture') });
    await expect(page.getByTestId('error-screen')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'UNSUPPORTED CAPTURE' })).toBeVisible();
    await page.getByRole('button', { name: 'Back' }).click();
    await expect(page.getByTestId('landing')).toBeVisible();
  });
});
