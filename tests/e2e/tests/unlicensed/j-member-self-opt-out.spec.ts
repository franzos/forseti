// Scenario J: a member can opt out of the org directory, and the opt-out is
// honoured against peers but not against an owner.
//
// With the directory open (`all`), one member hides their own row; a second
// member then no longer sees them, while the owner (admin) still does, marked
// with a "Hidden" badge. The self-toggle path (`members/{id}/hidden`,
// `hidden=true`) is a member-driven write the owner-only management forms
// can't reach — only a real session for the hiding member exercises it.
//
// Needs admin creds to flip the Default org to `all` and to read the
// owner-visible roster; skips otherwise.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { registerUser } from '../../helpers/register';
import { setVisibility } from '../../helpers/orgs';

test('member self-opt-out hides from peers but not the owner', async ({ page, browser }) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the opt-out scenario');

  // Admin (owner of Default) opens the directory so peers are mutually
  // visible to begin with.
  await signInAdminAal2(page, creds!);
  const opened = await setVisibility(page, 'all');
  expect(opened.status(), 'opening the directory should redirect').toBe(303);

  const hiderCtx = await browser.newContext();
  const peerCtx = await browser.newContext();
  const hiderPage = await hiderCtx.newPage();
  const peerPage = await peerCtx.newPage();
  try {
    const hider = await registerUser(hiderPage, 'playwright-optout-hider');
    await registerUser(peerPage, 'playwright-optout-peer');

    // Baseline: the peer sees the hider while the directory is open.
    await peerPage.goto('/settings/organization/members');
    expect((await peerPage.locator('body').innerText()).toLowerCase()).toContain(
      hider.email.toLowerCase(),
    );

    // The hider opts out via their own row's Hide control — the only
    // hidden-toggle form a plain member is shown.
    await hiderPage.goto('/settings/organization/members');
    const hide = hiderPage.locator('form[action$="/hidden"] button[type="submit"]');
    await expect(hide).toHaveText('Hide');
    await Promise.all([
      hiderPage.waitForURL((u) => u.pathname === '/settings/organization/members', {
        timeout: 15_000,
      }),
      hide.click(),
    ]);
    await expect(hiderPage.locator('form[action$="/hidden"] button[type="submit"]')).toHaveText('Show');

    // Peer no longer sees the hider.
    await peerPage.goto('/settings/organization/members');
    expect((await peerPage.locator('body').innerText()).toLowerCase()).not.toContain(
      hider.email.toLowerCase(),
    );

    // Owner still sees the hider, badged "Hidden".
    await page.goto('/settings/organization/members');
    const ownerBody = await page.locator('body').innerText();
    expect(ownerBody.toLowerCase()).toContain(hider.email.toLowerCase());
    const hiderRow = page.locator('tr', { hasText: hider.email });
    await expect(hiderRow.getByText('Hidden')).toBeVisible();

    // Restore: un-hide so reruns start clean.
    await hiderPage.goto('/settings/organization/members');
    await Promise.all([
      hiderPage.waitForURL((u) => u.pathname === '/settings/organization/members', {
        timeout: 15_000,
      }),
      hiderPage.locator('form[action$="/hidden"] button[type="submit"]').click(),
    ]);
  } finally {
    await hiderCtx.close();
    await peerCtx.close();
    // Restore the seeded default so Scenario I (and reruns) see admins_only.
    await setVisibility(page, 'admins_only');
  }
});
