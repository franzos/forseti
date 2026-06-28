// Scenario L: buttons keep a pointer cursor.
//
// Tailwind v4 dropped the v3 default of `cursor: pointer` on buttons; a base
// rule restores it (commit "fix: pointer cursor on buttons"). This is a pure
// compiled-CSS guarantee — invisible to Rust tests — so a thin smoke test on
// the rendered stylesheet guards the regression.
import { test, expect } from '@playwright/test';

test('a primary button computes cursor:pointer', async ({ page }) => {
  await page.goto('/login');
  const button = page.locator('button[name="method"][value="password"]');
  await expect(button).toBeVisible();
  const cursor = await button.evaluate((el) => getComputedStyle(el).cursor);
  expect(cursor).toBe('pointer');
});
