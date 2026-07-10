// Scenario H (licensed): external self-serve join via the public landing
// page.
//
// Admin creates an external org (create-time defaults: admins-only
// directory + public login enabled, spec §4). A fresh browser context then
// walks the real signup path: /o/<slug> -> the register CTA carries
// return_to=/join/confirm?org=<slug> -> Kratos registration -> lands
// authenticated on /join/confirm -> explicit CSRF-confirmed POST writes the
// membership row. Unlike the invite-redemption scenario, the email is
// deliberately left unverified: Model 1 join has no verification gate.
//
// Needs admin creds + an active Orgs license; skips without creds.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { createOrg, orgBase } from '../../helpers/orgs';
import { uniqueEmail, registerUserWithEmail } from '../../helpers/register';

test('external landing signup: register → /join/confirm → member of target org, not Default', async ({
  browser,
  page,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(
    !creds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the external self-serve join scenario',
  );

  // 1. Admin signs in and creates an external org (licensed multi-org form).
  await signInAdminAal2(page, creds!);
  const stamp = Date.now();
  const orgName = `Selfserve ${stamp}`;
  const slug = await createOrg(page, orgName, `selfserve-${stamp}`, 'external');

  const joinerEmail = uniqueEmail('playwright-selfserve');

  // 2. Fresh browser context — no admin cookies — visits the landing page.
  const joinerContext = await browser.newContext();
  const joinerPage = await joinerContext.newPage();
  try {
    await joinerPage.goto(`/o/${slug}`);

    // The register CTA is bound to a Kratos registration URL carrying
    // return_to=/join/confirm?org=<slug> (src/orgs/public_landing.rs::register_href).
    const registerLink = joinerPage.locator('a', { hasText: 'Create an account' });
    await expect(registerLink).toBeVisible();
    const href = await registerLink.getAttribute('href');
    expect(href, 'register CTA missing href').toBeTruthy();
    expect(href!).toContain(encodeURIComponent(`/join/confirm?org=${slug}`));

    // 3. Click through to Kratos registration and complete it. The CTA click
    //    already landed us on a registration flow carrying the
    //    return_to=/join/confirm, so complete THAT flow — skipInitialGoto keeps
    //    the helper from re-navigating to a fresh flow and dropping return_to.
    await Promise.all([
      joinerPage.waitForURL((u) => u.pathname.startsWith('/registration'), { timeout: 15_000 }),
      registerLink.click(),
    ]);
    await registerUserWithEmail(joinerPage, joinerEmail, { skipInitialGoto: true });

    // 4. Registration's after-hook return_to lands the joiner on
    //    /join/confirm?org=<slug>, signed in. No email-verification step —
    //    that's the point of Model 1 (no verification gate before join).
    await joinerPage.waitForURL((u) => u.pathname === '/join/confirm', { timeout: 15_000 });

    // 5. Explicit CSRF-confirmed POST writes the membership row.
    const confirmBtn = joinerPage.locator('form[action="/join/confirm"] button[type="submit"]');
    await expect(confirmBtn).toBeVisible({ timeout: 15_000 });
    await Promise.all([
      joinerPage.waitForURL((u) => u.pathname === '/' || u.pathname.startsWith('/settings'), {
        timeout: 15_000,
      }),
      confirmBtn.click(),
    ]);

    // 6. The joiner lands in the target org, not Default: visible on the
    //    target org's members page, absent from Default's.
    await joinerPage.goto(`${orgBase(slug)}/members`);
    const targetBody = await joinerPage.locator('body').innerText();
    expect(targetBody.toLowerCase()).toContain(joinerEmail.toLowerCase());
  } finally {
    await joinerContext.close();
  }

  // 7. Confirm the joiner never lands in Default (admin's own view of the
  //    default org's member list).
  await page.goto(`${orgBase(null)}/members`);
  const defaultBody = await page.locator('body').innerText();
  expect(defaultBody.toLowerCase()).not.toContain(joinerEmail.toLowerCase());
});
