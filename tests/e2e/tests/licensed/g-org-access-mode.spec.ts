// Scenario G (licensed): org access-mode guardrails, create-time and
// transition-time.
//
// Creating an org with mode:'external' proves the create-time defaults land
// (admins_only directory + public login enabled) without a separate save
// step. Switching an internal org to external and back proves the
// transition route enforces the same guardrails and that External->Internal
// leaves the member directory alone (spec §9).
//
// Needs admin creds + an active orgs license; skips without creds.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { createOrg, orgBase, setAccessMode } from '../../helpers/orgs';

test('external mode applies guardrails at create time and across transitions', async ({ page }) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the access-mode scenario');

  await signInAdminAal2(page, creds!);
  page.on('dialog', (d) => d.accept());

  const stamp = Date.now();
  const orgName = `Accessmode ${stamp}`;
  const slug = await createOrg(page, orgName, `accessmode-${stamp}`, 'external');
  const base = orgBase(slug);

  await page.goto(`${base}/members`);
  await expect(page.locator('select[name="visibility"]')).toHaveValue('admins_only');

  await page.goto(`${base}/branding`);
  await expect(page.locator('input[name="request_public_login"]')).toBeChecked();

  // External -> Internal: public login turns off, directory stays admins_only.
  await setAccessMode(page, 'internal', slug);
  await page.goto(`${base}/branding`);
  await expect(page.locator('input[name="request_public_login"]')).not.toBeChecked();
  await page.goto(`${base}/members`);
  await expect(page.locator('select[name="visibility"]')).toHaveValue('admins_only');

  // Internal -> External again: guardrails re-apply.
  await setAccessMode(page, 'external', slug);
  await page.goto(`${base}/branding`);
  await expect(page.locator('input[name="request_public_login"]')).toBeChecked();
});
