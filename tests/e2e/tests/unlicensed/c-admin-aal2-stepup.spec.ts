// Scenario C: AAL2 step-up at /admin/*.
//
// The Rust suite has the admin fixture log in at AAL2 *before* hitting
// any admin URL, so it never observes the step-up redirect chain. This
// scenario deliberately signs in at AAL1, hits /admin/webhooks, and
// asserts the portal redirects to /login?aal=aal2 (or surfaces the TOTP
// form). Then submits TOTP and lands on the dead-letter page.
//
// Skips when admin env vars aren't set.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv } from '../../helpers/admin';
import { signInAal1 } from '../../helpers/register';
import { computeTotp } from '../../helpers/totp';

test('AAL2 step-up triggers at /admin/webhooks for an AAL1-only session', async ({ page }) => {
  const creds = adminCredsFromEnv();
  test.skip(
    !creds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the admin AAL2 step-up scenario',
  );

  // 1. AAL1 sign-in (password only).
  await signInAal1(page, creds!.email, creds!.password);

  // 2. Hit /admin/webhooks. The portal's admin gate emits a 303 to
  //    `/login?aal=aal2&return_to=/admin/webhooks`, which the /login
  //    handler turns into a Kratos browser-init that 303s again to
  //    `/login?flow=<id>` (Kratos strips `aal=` from the URL but bakes
  //    AAL2 into the flow's server-side context — see
  //    `src/auth/login.rs`). The visible outcome: a TOTP form is
  //    rendered on a /login URL.
  await page.goto('/admin/webhooks');
  const totpInput = page.locator('input[name="totp_code"]');
  await totpInput.waitFor({ state: 'visible', timeout: 15_000 });

  // The URL is `/login?flow=<uuid>` at this point — Kratos rewrote it.
  // What matters: we're on /login with a TOTP prompt. (If we were AAL2
  // already, the admin page would have rendered directly; if we weren't
  // allow-listed, we'd be on an Access denied page.)
  expect(page.url()).toMatch(/\/login/);

  // 3. Submit a fresh TOTP code. After success, the flow's `return_to`
  //    (baked in by the /login handler from the original query) drives
  //    the redirect to /admin/webhooks.
  await totpInput.fill(computeTotp(creds!.totpSecret));
  await page.locator('button[name="method"][value="totp"]').click();
  await page.waitForURL((u) => u.pathname === '/admin/webhooks', { timeout: 15_000 });

  // 4. Landed on /admin/webhooks. Sanity-check we're on the dead-letter
  //    page proper — neither the "Access denied" admin-allowlist error
  //    nor the /login form.
  const bodyText = await page.locator('body').innerText();
  expect(bodyText).not.toMatch(/Access denied/);
  expect(bodyText).not.toMatch(/Sign in/);
});
