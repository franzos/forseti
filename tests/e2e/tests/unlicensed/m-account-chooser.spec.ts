// Scenario M: multi-account chooser — remember opt-in + cross-account switch.
//
// When a user grants consent with the "Remember this account on this device"
// checkbox checked, the portal sets a `forseti_known_accounts` cookie on the
// portal origin. On subsequent consent pages, remembered accounts (other than
// the current subject) are listed as a "Switch account" chooser. Submitting a
// chooser form tears down the current Kratos session and restarts the same
// OAuth flow, landing the browser on /login.
//
// Uses the same admin-gated pattern as Scenario B (create an OAuth client with
// consent enabled, then drive the browser flow). Skips when admin env vars
// aren't set.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { createOAuthClient } from '../../helpers/clients';
import { logout, registerUser } from '../../helpers/register';
import { generatePkcePair } from '../../helpers/oauth';

// Same issuer hostname constants as Scenario B — Hydra's CSRF cookie is scoped
// to this hostname; using `localhost:4444` breaks consent (403 CSRF mismatch).
const HYDRA_AUTHORIZE = 'http://host.containers.internal:4444/oauth2/auth';

// Unreachable callback — same trick as Scenario B: listen for the navigation
// request and read `code` off the URL before ERR_CONNECTION_REFUSED fires.
const REDIRECT_URI = 'http://localhost:9876/cb';

/** Build a PKCE authorize URL for the given client and return the URL string. */
function buildAuthorizeUrl(clientId: string, pkce: ReturnType<typeof generatePkcePair>, state: string): string {
  const url = new URL(HYDRA_AUTHORIZE);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', pkce.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

test('account chooser: remember opt-in persists across sessions; switch restarts flow', async ({ page }) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the admin-gated account chooser scenario',
  );

  // 1. Admin creates a fresh OAuth client with consent enabled. The client
  //    name is timestamped to avoid collisions with parallel CI runs.
  await signInAdminAal2(page, adminCreds!);
  const { clientId } = await createOAuthClient(page, {
    name: `pw-chooser-${Date.now()}`,
    redirectUri: REDIRECT_URI,
    scope: 'openid email profile',
    skipConsent: false,
  });
  await logout(page);

  // 2. Register user A and drive the authorize → consent flow. Check the
  //    "Remember this account" box, then click Allow and capture the callback.
  const aUser = await registerUser(page, 'pw-chooser-a');

  const pkceA = generatePkcePair();
  const stateA = `e2e-chooser-a-${Date.now()}`;
  await page.goto(buildAuthorizeUrl(clientId, pkceA, stateA));

  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
    { timeout: 15_000 },
  );
  if (!page.url().includes('/oauth/consent')) {
    throw new Error(
      `expected /oauth/consent after authorize; landed on ${page.url()} — consent may have been auto-granted (skip_consent=true)`,
    );
  }

  // The remember checkbox is the new "remember on this device" field — distinct
  // from Hydra's own `name="remember"` (which persists the consent grant).
  const rememberA = page.locator('form[action="/oauth/consent"] input[name="remember_account"]');
  await expect(rememberA).toBeVisible();
  await rememberA.check();

  const navPromiseA = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
  await page
    .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
    .click();
  const reqA = await navPromiseA;
  const callbackUrlA = new URL(reqA.url());
  expect(callbackUrlA.searchParams.get('code')).toBeTruthy();

  // 3. Assert the forseti_known_accounts cookie was set on the portal origin.
  const cookiesAfterA = await page.context().cookies();
  const knownAccountsCookieA = cookiesAfterA.find((c) => c.name === 'forseti_known_accounts');
  expect(knownAccountsCookieA).toBeTruthy();
  expect(knownAccountsCookieA!.value).toBeTruthy();

  // 4. Log A out, register user B, drive the same consent flow with remember
  //    checked. After this both A and B are stored in the known-accounts cookie.
  await logout(page);
  const bUser = await registerUser(page, 'pw-chooser-b');

  const pkceB = generatePkcePair();
  const stateB = `e2e-chooser-b-${Date.now()}`;
  await page.goto(buildAuthorizeUrl(clientId, pkceB, stateB));

  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
    { timeout: 15_000 },
  );
  if (!page.url().includes('/oauth/consent')) {
    throw new Error(
      `expected /oauth/consent after authorize for user B; landed on ${page.url()}`,
    );
  }

  const rememberB = page.locator('form[action="/oauth/consent"] input[name="remember_account"]');
  await expect(rememberB).toBeVisible();
  await rememberB.check();

  const navPromiseB = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
  await page
    .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
    .click();
  const reqB = await navPromiseB;
  const callbackUrlB = new URL(reqB.url());
  expect(callbackUrlB.searchParams.get('code')).toBeTruthy();

  // 5. Start a third authorize as B (still signed in as B). The consent page
  //    should now render the "Switch account" chooser listing A (not B, because
  //    the current subject is excluded from the chooser).
  const pkceC = generatePkcePair();
  const stateC = `e2e-chooser-c-${Date.now()}`;
  await page.goto(buildAuthorizeUrl(clientId, pkceC, stateC));

  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
    { timeout: 15_000 },
  );
  if (!page.url().includes('/oauth/consent')) {
    throw new Error(
      `expected /oauth/consent for third authorize; landed on ${page.url()}`,
    );
  }

  // 6. Assert the chooser is present and lists A but not B.
  const switchForms = page.locator('form[action="/oauth/consent/switch"]');
  const switchCount = await switchForms.count();
  expect(switchCount).toBeGreaterThanOrEqual(1);

  // The current subject (B) must not appear in any switch form. A must appear.
  // We check A's email is visible somewhere in the chooser region, and B's
  // email is absent — the server excludes the signed-in subject from the list.
  await expect(page.getByText(aUser.email)).toBeVisible();
  // B's email must not appear inside a switch form (the current session is B).
  const bInChooser = await switchForms.filter({ hasText: bUser.email }).count();
  expect(bInChooser).toBe(0);

  // Each switch form carries the identity_id (a UUID) and the consent_challenge
  // as hidden inputs. Verify the shape of the first form's hidden inputs.
  const firstSwitchForm = switchForms.first();
  const identityIdInput = firstSwitchForm.locator('input[name="identity_id"]');
  const identityIdValue = await identityIdInput.getAttribute('value');
  expect(identityIdValue).toMatch(/^[0-9a-f-]{36}$/);

  // 7. Submit the switch form for A. The portal tears down B's Kratos session
  //    and restarts the OAuth flow, which lands on /login (Phase 1 does not
  //    prefill the identifier field — do not assert prefill).
  await firstSwitchForm.locator('button[type="submit"]').click();
  await page.waitForURL((u) => u.pathname.startsWith('/login'), { timeout: 15_000 });

  // Confirm B's session is gone: an unauthenticated GET to / redirects to /login.
  await page.goto('/');
  await expect(page).toHaveURL(/\/login/);
});
