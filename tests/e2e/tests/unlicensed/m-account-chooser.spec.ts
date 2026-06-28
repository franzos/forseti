// Scenario M: multi-account chooser — remember opt-in + cross-account switch.
//
// When a user grants consent with the "Remember this account on this device"
// checkbox checked, the portal sets a `forseti_known_accounts` cookie on the
// portal origin. On a later consent page for a different signed-in user, the
// remembered account is offered as a "Switch account" chooser. Submitting a
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

test('account chooser: remember opt-in renders + switch restarts flow', async ({ page }) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the admin-gated account chooser scenario',
  );

  // 1. Admin creates a fresh OAuth client with consent enabled. Timestamped
  //    name avoids collisions with parallel CI runs.
  await signInAdminAal2(page, adminCreds!);
  const { clientId } = await createOAuthClient(page, {
    name: `pw-chooser-${Date.now()}`,
    redirectUri: REDIRECT_URI,
    scope: 'openid email profile',
    skipConsent: false,
  });
  await logout(page);

  // 2. Register user A, drive authorize → consent, tick "Remember this account
  //    on this device", click Allow, capture the callback code.
  const aUser = await registerUser(page, 'pw-chooser-a');

  const pkceA = generatePkcePair();
  const stateA = `e2e-chooser-a-${Date.now()}`;
  await page.goto(buildAuthorizeUrl(clientId, pkceA, stateA));
  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
    { timeout: 15_000 },
  );
  if (!page.url().includes('/oauth/consent')) {
    throw new Error(`expected /oauth/consent for user A; landed on ${page.url()}`);
  }

  // The remember checkbox is the new "remember on this device" field — distinct
  // from Hydra's own `name="remember"` (which persists the consent grant).
  const rememberA = page.locator('form[action="/oauth/consent"] input[name="remember_account"]');
  await expect(rememberA).toBeVisible();
  await rememberA.check();

  // Capture the code off the navigation request to the unreachable callback
  // (same trick as Scenario B). The browser then drifts to an error page for
  // that host; the next portal navigation (logout) can race it, which the
  // suite's `retries: 1` absorbs.
  const navPromiseA = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
  await page
    .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
    .click();
  const reqA = await navPromiseA;
  expect(new URL(reqA.url()).searchParams.get('code')).toBeTruthy();

  // 3. The grant set the forseti_known_accounts cookie on the portal origin.
  const cookiesAfterA = await page.context().cookies();
  const knownAccountsCookie = cookiesAfterA.find((c) => c.name === 'forseti_known_accounts');
  expect(knownAccountsCookie).toBeTruthy();
  expect(knownAccountsCookie!.value).toBeTruthy();

  // 4. Log A out and sign in as a different user B (NOT remembered). B's first
  //    consent for this client renders (Hydra only auto-skips re-consent for a
  //    subject that already granted the client), and because A is remembered on
  //    this device, the consent page offers A in the "Switch account" chooser.
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
    throw new Error(`expected /oauth/consent for user B; landed on ${page.url()}`);
  }

  // 5. The chooser lists A (remembered) but not B (the current subject is
  //    excluded server-side).
  const switchForms = page.locator('form[action="/oauth/consent/switch"]');
  expect(await switchForms.count()).toBeGreaterThanOrEqual(1);
  await expect(page.getByText(aUser.email)).toBeVisible();
  expect(await switchForms.filter({ hasText: bUser.email }).count()).toBe(0);

  // Each switch form carries the target identity UUID as a hidden input.
  const firstSwitchForm = switchForms.first();
  const identityIdValue = await firstSwitchForm.locator('input[name="identity_id"]').getAttribute('value');
  expect(identityIdValue).toMatch(/^[0-9a-f-]{36}$/);

  // 6. Submit the switch form. The portal tears down B's Kratos session and
  //    restarts the OAuth flow with prompt=login, landing on /login (Phase 1
  //    does not prefill the identifier — do not assert prefill).
  await firstSwitchForm.locator('button[type="submit"]').click();
  await page.waitForURL((u) => u.pathname.startsWith('/login'), { timeout: 15_000 });

  // B's session is gone: an unauthenticated GET to / redirects to /login.
  await page.goto('/');
  await expect(page).toHaveURL(/\/login/);
});
