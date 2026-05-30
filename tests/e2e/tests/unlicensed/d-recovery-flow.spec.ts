// Scenario D: forgot-password recovery end-to-end.
//
// The Rust suite covers the Kratos recovery-code hand-off in isolation
// (`bug_regressions.rs::recovery_links_to_settings_password`); what it
// doesn't exercise is the *browser-side* state machine after the code is
// submitted — Kratos drops the user on a privileged settings flow which
// the portal renders as `/settings/password?flow=...`. This scenario
// drives that path with a real cookie jar so the privileged-session
// redirect chain (recovery → settings flow → password form) actually
// runs through Chromium.
//
// No admin env vars needed.
import { test, expect } from '@playwright/test';
import { registerUser, logout } from '../../helpers/register';
import { waitForMail, extractSixDigitCode } from '../../helpers/mailcrab';

const NEW_PASSWORD = 'Sup3rSecret-Recovery-Replaced!';

test('forgot-password recovery resets the password and signs back in', async ({
  page,
  request,
}) => {
  // 1. Register a fresh user (AAL1 only — no TOTP), then log out so the
  //    recovery flow runs against a cold cookie jar.
  const { email } = await registerUser(page, 'playwright-recovery');
  await logout(page);

  // 2. Land on /recovery and submit the email. The portal proxies the
  //    code method's `email` input to Kratos which 303s back to
  //    /recovery?flow=<id> with the code input rendered.
  await page.goto('/recovery');
  await page.locator('input[name="email"]').fill(email);
  await Promise.all([
    // After submit Kratos's `sent_email` state lands on /recovery?flow=
    // with the code input visible.
    page.locator('input[name="code"]').waitFor({ state: 'visible', timeout: 15_000 }),
    page.locator('button[name="method"][value="code"]').click(),
  ]);
  expect(page.url()).toMatch(/\/recovery\?flow=/);

  // 3. Pull the 6-digit recovery code from Mailcrab. Kratos's default
  //    courier template subject is "Use code <NNNNNN> to recover access
  //    to your account" — match on the stable substring.
  const mail = await waitForMail(request, email, 'recover access', 15_000);
  const code = extractSixDigitCode(mail.body);

  // 4. Submit the code on the same /recovery?flow= page. Kratos accepts,
  //    issues a privileged settings session, and 303s to
  //    /settings/password?flow=... where the user can set a new password.
  await page.locator('input[name="code"]').fill(code);
  await Promise.all([
    page.waitForURL(/\/settings\/password\?flow=/, { timeout: 15_000 }),
    page.locator('button[name="method"][value="code"]').click(),
  ]);

  // 5. Set the new password. The form's `method=password` submit posts
  //    cross-origin to Kratos which 303s back to /settings/password with
  //    the success state, then the portal's after-hook (or the form's
  //    return_to) lands us on /.
  await page.locator('input[name="password"]').fill(NEW_PASSWORD);
  await page.locator('button[name="method"][value="password"]').click();
  // The password submit may keep us on /settings/password with a success
  // banner (Kratos's "Your changes have been saved" message), or bounce
  // to /. Either is a pass — we only need the password to actually have
  // been changed, which we verify in step 6+ by signing back in.
  await page.waitForLoadState('networkidle', { timeout: 15_000 });
  expect(page.url()).not.toMatch(/\/recovery/);

  // 6. Log out, then sign in with the NEW password to prove the change
  //    landed. (Signing in without logging out first would re-use the
  //    existing privileged session and wouldn't actually exercise the
  //    new credential.)
  await logout(page);

  await page.goto('/login');
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill(NEW_PASSWORD);
  await page.locator('button[name="method"][value="password"]').click();
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });

  // 7. Confirm dashboard renders — i.e. we're authenticated under the
  //    new credential. The dashboard heading copy is brand-dependent, so
  //    just assert we ended on / or a known post-login surface.
  expect(page.url()).toMatch(/(?:\/|\/verification|\/settings)/);
});
