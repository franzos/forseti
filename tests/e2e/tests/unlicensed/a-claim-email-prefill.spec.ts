// Scenario A: claim-email full round-trip including the rendered prefill.
//
// The Rust integration suite asserts the 303 → /registration?prefill_email=…
// + Set-Cookie behaviour (`claim_email_confirm_redirects_to_registration_with_prefill`).
// What it descopes — and what this scenario covers — is the rendered DOM
// after Kratos's `browser` flow init: the `traits.email` input on the
// post-redirect /registration page must carry the freed email.
import { test, expect } from '@playwright/test';
import { registerUser, logout, uniqueEmail } from '../../helpers/register';
import { waitForMail, extractSixDigitCode } from '../../helpers/mailcrab';

test('claim-email confirm pre-fills the registration form', async ({ page, request }) => {
  // 1. Register an unverified user, then log them out so the claim-email
  //    flow doesn't refuse on the "your session owns this email" path.
  const { email } = await registerUser(page, 'playwright-claim');
  await logout(page);

  // 2. Drive /claim-email and submit the address. The handler posts a
  //    code to Mailcrab and 303s us to /claim-email/confirm?token=…
  await page.goto('/claim-email');
  await page.locator('input[name="email"]').fill(email);
  await Promise.all([
    page.waitForURL(/\/claim-email\/confirm\?token=/),
    page.locator('form[action="/claim-email"] button[type="submit"]').click(),
  ]);

  // 3. Pull the 6-digit code from Mailcrab. The portal-owned mail
  //    template's subject is "Confirm your email for …" — match a stable
  //    prefix.
  const mail = await waitForMail(request, email, 'Confirm your email', 15_000);
  const code = extractSixDigitCode(mail.body);

  // 4. Submit the code. Expect a 303 to /registration with the email
  //    prefilled — Playwright auto-follows the redirect and lands us on
  //    the Kratos-browser-init registration page.
  await page.locator('input[name="code"]').fill(code);
  await Promise.all([
    page.waitForURL((u) => u.pathname.startsWith('/registration')),
    page.locator('form[action="/claim-email/confirm"] button[type="submit"]').click(),
  ]);

  // 5. The bit the Rust suite couldn't easily verify: after Kratos's
  //    browser-init round-trip, the rendered `traits.email` input must
  //    carry the freed email. The portal reads `portal_prefill_email`
  //    cookie (set on the 303) and falls back to the `prefill_email`
  //    query param when no cookie is present.
  const emailInput = page.locator('input[name="traits.email"]');
  await expect(emailInput).toHaveValue(email);
});
