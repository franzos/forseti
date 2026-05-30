// Scenario E: OIDC RP-initiated logout end-to-end.
//
// Hydra's `/oauth2/sessions/logout?id_token_hint=...` lands on the
// portal's `/oauth/logout` confirm page. Submitting the form tears down
// the Kratos session AND accepts the Hydra logout challenge, which
// redirects to the registered `post_logout_redirect_uri`. The Rust
// suite verifies the Hydra-side handshake; what's browser-specific is
// the confirm-page render + the cookie clear + the post-logout
// redirect actually landing.
//
// Skips when admin env vars aren't set (needs admin to create the OAuth
// client).
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { logout, registerUser } from '../../helpers/register';
import { createOAuthClient } from '../../helpers/clients';
import { generatePkcePair } from '../../helpers/oauth';

const HYDRA_AUTHORIZE = 'http://host.containers.internal:4444/oauth2/auth';
const HYDRA_TOKEN = 'http://host.containers.internal:4444/oauth2/token';
const HYDRA_LOGOUT = 'http://host.containers.internal:4444/oauth2/sessions/logout';
const KRATOS_PUBLIC = 'http://host.containers.internal:4433';

const REDIRECT_URI = 'http://localhost:9876/cb';
const POST_LOGOUT_URI = 'http://localhost:9876/post-logout';

test('RP-initiated logout clears the session and redirects to post_logout_redirect_uri', async ({
  page,
  request,
}) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the RP-initiated logout scenario',
  );

  // 1. Admin signs in (AAL2) and creates an OAuth client with a
  //    post_logout_redirect_uri so Hydra can redirect after accept.
  await signInAdminAal2(page, adminCreds!);
  const { clientId, clientSecret } = await createOAuthClient(page, {
    name: `playwright-rp-logout-${Date.now()}`,
    redirectUri: REDIRECT_URI,
    postLogoutRedirectUris: [POST_LOGOUT_URI],
  });

  // 2. Log the admin out, register a fresh end-user, drive the OAuth
  //    authorize → consent → token exchange so we have an `id_token` to
  //    use as the `id_token_hint`.
  await logout(page);
  await registerUser(page, 'playwright-rp-logout-user');

  const pkce = generatePkcePair();
  const state = `e2e-state-${Date.now()}`;
  const authUrl = new URL(HYDRA_AUTHORIZE);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid email profile offline_access');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', pkce.challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  await page.goto(authUrl.toString());
  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
  );

  // Capture the authorization code off the unreachable callback (same
  // pattern as Scenario B — don't waitForURL on the callback host).
  const navPromise = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
  await page
    .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
    .click();
  const cbReq = await navPromise;
  const code = new URL(cbReq.url()).searchParams.get('code');
  expect(code).toBeTruthy();

  // 3. Exchange the code for tokens; we need `id_token` as the hint.
  const tokenRes = await request.post(HYDRA_TOKEN, {
    form: {
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: pkce.verifier,
    },
  });
  expect(tokenRes.ok()).toBeTruthy();
  const tokens = (await tokenRes.json()) as { id_token: string };
  expect(tokens.id_token).toBeTruthy();

  // 4. Drive RP-initiated logout. Hydra mints a `logout_challenge` and
  //    303s to the portal's `/oauth/logout?logout_challenge=...`
  //    confirm page.
  const logoutState = `plw-logout-${Date.now()}`;
  const logoutUrl = new URL(HYDRA_LOGOUT);
  logoutUrl.searchParams.set('id_token_hint', tokens.id_token);
  logoutUrl.searchParams.set('post_logout_redirect_uri', POST_LOGOUT_URI);
  logoutUrl.searchParams.set('state', logoutState);

  await page.goto(logoutUrl.toString());

  // 5. Assert: confirm page rendered. The portal template's heading is
  //    "Sign out of all apps?" and the submit button says "Sign out".
  //    Match the button label rather than the heading copy so a small
  //    h1 rewrite doesn't flake the test.
  await expect(
    page.locator('form[action="/oauth/logout"] button[type="submit"]'),
  ).toBeVisible();
  expect(page.url()).toMatch(/\/oauth\/logout/);

  // 6. Click "Sign out". The portal does the Kratos session teardown +
  //    Hydra accept_logout, then 303s to the post_logout_redirect_uri.
  //    `localhost:9876` is unreachable — capture the navigation request
  //    instead of waiting for the URL.
  const postLogoutNav = page.waitForRequest((req) =>
    req.url().startsWith(POST_LOGOUT_URI),
  );
  await page.locator('form[action="/oauth/logout"] button[type="submit"]').click();
  const postLogoutReq = await postLogoutNav;
  const postLogoutUrl = new URL(postLogoutReq.url());
  expect(postLogoutUrl.searchParams.get('state')).toBe(logoutState);

  // 7. Assert: the Kratos session is actually gone. A `to_session` call
  //    re-using the browser's cookies must return 401. We pull cookies
  //    out of the page's context and pass them through a fresh
  //    `request.get` so the assertion isn't fooled by Playwright's
  //    request-context isolation.
  const cookies = await page.context().cookies();
  const cookieHeader = cookies
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
  const whoamiRes = await request.get(`${KRATOS_PUBLIC}/sessions/whoami`, {
    headers: { cookie: cookieHeader },
    failOnStatusCode: false,
  });
  expect(whoamiRes.status()).toBe(401);
});
