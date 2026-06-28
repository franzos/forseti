// Admin sign-in helper. Forseti's admin surface requires an
// allow-listed email at AAL2 (TOTP). We mirror the Rust suite's
// env-var contract:
//
//   FORSETI_ADMIN_TEST_EMAIL    — admin email (must be in [admin].allowed_emails)
//   FORSETI_ADMIN_TEST_PASSWORD — admin password
//   FORSETI_ADMIN_TEST_TOTP_SECRET — base32 TOTP secret (REQUIRED; we don't
//                                   accept the single-code _CODE fallback
//                                   because every admin scenario needs
//                                   multiple fresh codes per run)
//
// Returns null when env vars are missing — tests should skip rather than
// fail in that case.
import type { Page } from '@playwright/test';
import { computeTotp } from './totp';
import { signInAal1 } from './register';

export interface AdminCreds {
  email: string;
  password: string;
  totpSecret: string;
}

export function adminCredsFromEnv(): AdminCreds | null {
  const email = process.env.FORSETI_ADMIN_TEST_EMAIL;
  const password = process.env.FORSETI_ADMIN_TEST_PASSWORD;
  const totpSecret = process.env.FORSETI_ADMIN_TEST_TOTP_SECRET;
  if (!email || !password || !totpSecret) return null;
  return { email, password, totpSecret };
}

/**
 * Sign in the admin all the way to AAL2 (password + TOTP). Lands wherever
 * the after-hook redirects (usually `/`). Caller can then navigate to any
 * `/admin/*` URL.
 *
 * After a fresh AAL1 password submit, Kratos may either (a) drop us back
 * on `/login?aal=aal2` because the session needs step-up, or (b) skip
 * straight to a TOTP-only flow. Either way the cookie jar carries an
 * AAL1 `ory_kratos_session`; navigating to `/login?aal=aal2` always
 * surfaces the TOTP form for an enrolled user.
 */
export async function signInAdminAal2(page: Page, creds: AdminCreds): Promise<void> {
  await signInAal1(page, creds.email, creds.password);

  // The password step either landed us off `/login` with an AAL1 session, or
  // (with `session.whoami.required_aal: highest_available`) advanced straight
  // into the in-flow AAL2 form at `/login?flow=…`. Only force the explicit
  // step-up flow when the TOTP form isn't already showing.
  let totpInput = page.locator('input[name="totp_code"]');
  if (!(await totpInput.isVisible().catch(() => false))) {
    // What an admin sees in the wild when they hit any `/admin/*` URL with
    // only an AAL1 session.
    await page.goto('/login?aal=aal2');
    totpInput = page.locator('input[name="totp_code"]');
  }
  // The lookup_secret input also has `required` set on it (e2e-review skill's
  // "Known traps") but Playwright's `.click()` on the totp-named submit button
  // works because Playwright submits with the right submitter; the
  // browser-side validity check only fires on visible required inputs and
  // Kratos templates hide the lookup_secret when the totp screen is showing.
  await totpInput.waitFor({ state: 'visible' });
  await totpInput.fill(computeTotp(creds.totpSecret));
  await Promise.all([
    page.waitForURL((u) => !u.pathname.startsWith('/login')),
    page.locator('button[name="method"][value="totp"]').click(),
  ]);
}
