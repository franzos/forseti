// Scenario K: teams are a commercial surface even on the Default org.
//
// `require_team_admin` gates `Feature::Orgs` everywhere, so an owner hitting
// /settings/organization/teams on an unlicensed install gets the upsell page
// — not a working CRUD surface. (Owner check runs first, so this must be the
// owner: a non-owner would 403 before the gate.) The upsell vs. real-page
// fork is data-driven off license state and can't be unit-tested through the
// rendered chrome.
//
// Needs admin creds (the admin owns the Default org); skips otherwise.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';

test('teams page renders the upsell, not a CRUD page, when unlicensed', async ({ page }) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the teams upsell scenario');

  await signInAdminAal2(page, creds!);
  await page.goto('/settings/organization/teams');

  // Upsell chrome: the feature label heading + the activate-license CTA.
  await expect(page.getByRole('heading', { name: 'Organizations' })).toBeVisible();
  await expect(page.locator('a[href="/admin/license"]', { hasText: 'Activate an existing license' })).toBeVisible();

  // And NOT the working teams form.
  await expect(page.locator('form[action="/settings/organization/teams"]')).toHaveCount(0);
});
