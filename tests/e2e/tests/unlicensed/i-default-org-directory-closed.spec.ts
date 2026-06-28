// Scenario I: the Default org ships its member directory closed.
//
// The migration seeds the Default org at `admins_only`, so a plain member
// hitting /settings/organization/members must see only themselves and the
// "administrators only" policy statement — never a roster of every other
// account on the install. This is the OSS privacy default; the Rust tests
// cover the visibility predicate in isolation, but only a real browser proves
// the rendered members page actually withholds the other rows from a
// non-owner session.
import { test, expect } from '@playwright/test';
import { registerUser } from '../../helpers/register';

test('default org members page shows a plain member only themselves', async ({ page, browser }) => {
  // A first account so the directory has someone OTHER than the viewer to
  // (correctly) withhold. Its own context so its session doesn't bleed.
  const otherCtx = await browser.newContext();
  const otherPage = await otherCtx.newPage();
  let otherEmail = '';
  try {
    otherEmail = (await registerUser(otherPage, 'playwright-dir-other')).email;
  } finally {
    await otherCtx.close();
  }

  // The viewer registers second, so it is always a plain member (the first
  // account on a fresh install would have taken Default ownership).
  const viewer = await registerUser(page, 'playwright-dir-viewer');

  await page.goto('/settings/organization/members');
  await expect(page.getByText('Only administrators can see the full member list.')).toBeVisible();

  const body = (await page.locator('body').innerText()).toLowerCase();
  expect(body).toContain(viewer.email.toLowerCase());
  expect(body).not.toContain(otherEmail.toLowerCase());
});
