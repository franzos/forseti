// Drive the portal's two-step registration flow end-to-end via the browser.
// Mirrors `tests/integration/common.rs::register_test_user` but in
// Playwright's `Page` so the test exercises the actual rendered DOM
// (cross-origin form post to Kratos, session cookie back to the portal).
//
// Returns the email + password used so caller tests can log in again or
// claim the email.
import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

export interface RegisteredUser {
  email: string;
  password: string;
}

const DEFAULT_PASSWORD = 'Sup3rSecret-E2E-Password!';

/**
 * Build a unique email per test. Combines a prefix, the test info worker
 * index, and the current monotonic timestamp so concurrent retries don't
 * collide. (Workers stay at 1 per `playwright.config.ts`, but the suffix
 * is cheap insurance.)
 */
export function uniqueEmail(prefix: string): string {
  const stamp = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  return `${prefix}-${stamp}@example.com`;
}

/**
 * Register a fresh user via the portal's two-step flow. Lands on the
 * dashboard with `ory_kratos_session` in the cookie jar on success.
 */
export async function registerUser(page: Page, prefix: string): Promise<RegisteredUser> {
  const email = uniqueEmail(prefix);
  return registerUserWithEmail(page, email);
}

/** As `registerUser`, with a caller-supplied email. */
export async function registerUserWithEmail(page: Page, email: string): Promise<RegisteredUser> {
  await page.goto('/registration');

  // Step 1: profile fields. Kratos's `traits.*` inputs are rendered by
  // the portal directly; the form posts cross-origin to Kratos at :4433
  // which 303s back to /registration?flow=<id> with the password step
  // rendered.
  await page.locator('input[name="traits.email"]').fill(email);
  await page.locator('input[name="traits.name.first"]').fill('Test');
  await page.locator('input[name="traits.name.last"]').fill('User');
  await page.locator('button[name="method"][value="profile"]').click();
  // Don't just wait for URL — the URL stays under /registration through
  // the entire flow. Wait for the password input to actually appear in
  // the DOM after Kratos's 303 round-trip.
  await page.locator('input[name="password"]').waitFor({ state: 'visible', timeout: 15_000 });

  // Step 2: password. Hidden traits.* re-submit automatically.
  await page.locator('input[name="password"]').fill(DEFAULT_PASSWORD);
  await page.locator('button[name="method"][value="password"]').click();

  // Land on /, /verification, or /settings/profile depending on after-hooks.
  await page.waitForURL((u) => !u.pathname.startsWith('/registration'), { timeout: 15_000 });
  await expect(page).not.toHaveURL(/\/registration/);
  return { email, password: DEFAULT_PASSWORD };
}

/** Drive the portal's logout form on the current page. */
export async function logout(page: Page): Promise<void> {
  await page.goto('/');
  // The Sign Out form posts to /logout. Target by action so we don't
  // accidentally submit some other form on the page.
  await page.locator('form[action="/logout"] button[type="submit"]').click();
  await page.waitForURL((u) => u.pathname.startsWith('/login') || u.pathname === '/', {
    timeout: 10_000,
  });
}

/**
 * Sign in at AAL1 only (password, no TOTP). Used by Scenario C which
 * deliberately hits an admin URL pre-step-up to assert the redirect chain.
 */
export async function signInAal1(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button[name="method"][value="password"]').click();
  // The password submit settles in one of:
  //   - off /login            (an AAL1 session is enough; e.g. a member on /)
  //   - /login?aal=aal2&…     (an explicit step-up was requested)
  //   - /settings/2fa         (privileged-session step-up flow)
  //   - /login?flow=… showing the TOTP form: with `highest_available`
  //     (infra/kratos/kratos.yml) the whoami right after the password submit
  //     is AAL2-short, so the portal immediately re-inits a second login flow
  //     for the enrolled identity. The chain never rests on / — it settles on
  //     the second-factor form — so the visible TOTP input is the only signal
  //     that the password step advanced.
  // A single in-page poll covers every case; a real timeout still throws (no
  // false-green), and there is no losing Promise.race arm left to reject.
  await page.waitForFunction(
    () => {
      const path = window.location.pathname;
      const search = window.location.search;
      return (
        !path.startsWith('/login') ||
        search.includes('aal=aal2') ||
        search.includes('refresh=true') ||
        document.querySelector('input[name="totp_code"]') !== null
      );
    },
    undefined,
    { timeout: 15_000 },
  );
}
