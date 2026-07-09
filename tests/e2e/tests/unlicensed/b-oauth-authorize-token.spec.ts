// Scenario B: full OAuth authorize → consent → callback → token exchange.
//
// The Rust suite covers refresh-token rotation against Hydra but doesn't
// exercise the cross-origin browser dance (portal at :3000, Hydra at
// :4444). That's what this scenario covers — specifically the CSRF cookie
// scoping that breaks the moment you hit `localhost:4444` instead of the
// issuer hostname `host.containers.internal:4444` (see
// `.claude/skills/e2e-review/SKILL.md`, "Known traps").
//
// Skips when admin env vars aren't set (need an admin session to create
// the OAuth client).
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { logout, registerUser } from '../../helpers/register';
import { decodeJwtClaims, generatePkcePair } from '../../helpers/oauth';

// Use the issuer hostname so Hydra's CSRF cookie scopes correctly. The
// Rust suite uses `localhost:4444` for backend POSTs (no browser involved
// → no cookie scoping race), but the browser-driven authorize URL MUST
// match Hydra's `issuer` value (see `infra/hydra/hydra.yml`).
const HYDRA_AUTHORIZE = 'http://host.containers.internal:4444/oauth2/auth';
const HYDRA_TOKEN = 'http://host.containers.internal:4444/oauth2/token';
const KRATOS_ADMIN = 'http://host.containers.internal:4434';

// Unreachable callback — Playwright reads the code off `page.url()`
// before the redirect can actually load.
const REDIRECT_URI = 'http://localhost:9876/cb';

test('OAuth authorize → consent → token exchange end-to-end', async ({ page, request }) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the admin-gated OAuth scenario',
  );

  // 1. Admin signs in (AAL2) and creates a fresh OAuth client. The
  //    show page renders the client secret in a `<pre>` block under
  //    "Credentials: shown once".
  await signInAdminAal2(page, adminCreds!);

  // The /admin/clients/new picker step is just navigation — go straight
  // to the web_app preset form.
  await page.goto('/admin/clients/new?type=web_app');

  const clientName = `playwright-oauth-${Date.now()}`;
  await page.locator('input[name="name"]').fill(clientName);
  await page.locator('textarea[name="redirect_uris"]').fill(REDIRECT_URI);
  // Web-app preset defaults are correct; we just need to confirm the
  // scope contains openid email profile offline_access.
  await page.locator('input[name="scope"]').fill('openid email profile offline_access');
  // Make sure consent isn't skipped — we WANT to click Allow.
  const skipConsent = page.locator('input[name="skip_consent"]');
  if (await skipConsent.isChecked()) {
    await skipConsent.uncheck();
  }
  await Promise.all([
    page.waitForURL(/\/admin\/clients\/[a-f0-9-]+/),
    page.locator('form[action="/admin/clients"] button[type="submit"]').click(),
  ]);

  // Capture client_id from the URL and secret from the reveal banner.
  const clientId = page.url().match(/\/admin\/clients\/([a-f0-9-]+)/)?.[1];
  if (!clientId) throw new Error(`could not parse client_id from ${page.url()}`);
  const revealHeader = page.getByText('Credentials: shown once');
  await revealHeader.waitFor();
  // The secret lives in the first `<pre>` immediately after the header.
  const clientSecret = await page
    .locator('pre')
    .filter({ hasNot: page.locator(':scope > *') })
    .first()
    .innerText();
  expect(clientSecret).toMatch(/^\S{20,}$/);

  // 2. Log the admin out and register a fresh end-user; they're the one
  //    who'll grant consent. (We could re-use the admin session, but
  //    keeping the personas distinct mirrors a realistic flow.)
  await logout(page);

  const endUser = await registerUser(page, 'playwright-oauth-user');

  // 3. Drive the authorize URL. Hydra prompts login (we already have a
  //    session — Kratos accepts), then consent (we click Allow), then
  //    redirects to the unreachable callback with `?code=…`.
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

  // The page may flow through portal /oauth/login (auto-grant when a
  // session exists), then land on /oauth/consent. Wait for either the
  // consent page or the callback redirect.
  await page.waitForURL((u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'));

  if (page.url().includes('/oauth/consent')) {
    // Click Allow. The Allow button is the submit with `decision=accept`.
    // We don't `waitForURL` inside Promise.all because the callback host
    // is unreachable — Playwright surfaces ERR_CONNECTION_REFUSED before
    // `waitForURL` resolves. Instead, listen for the *navigation* and
    // capture the URL there.
    const navPromise = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
    await page
      .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
      .click();
    const req = await navPromise;
    const callbackUrl = new URL(req.url());
    expect(callbackUrl.searchParams.get('state')).toBe(state);
    const code = callbackUrl.searchParams.get('code');
    expect(code).toBeTruthy();

    // 4. Exchange the code for tokens via the Hydra token endpoint.
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
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      id_token: string;
      refresh_token?: string;
    };
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();

    // 5. Decode the id_token and confirm `sub` is the registered user's
    //    Kratos identity_id. Hydra's `sub` for the playground's identity
    //    schema is the Kratos identity UUID directly.
    const claims = decodeJwtClaims(tokens.id_token);
    const sub = claims.sub as string;
    expect(sub).toMatch(/^[0-9a-f-]{36}$/);

    // Cross-check sub against the live Kratos admin lookup. Kratos's
    // `?credentials_identifier=<email>` is an exact match on a single
    // identity.
    const lookup = await request.get(
      `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(endUser.email)}`,
    );
    expect(lookup.ok()).toBeTruthy();
    const identities = (await lookup.json()) as Array<{ id: string }>;
    expect(identities[0]?.id).toBe(sub);
  } else {
    throw new Error(
      `expected /oauth/consent after authorize; landed on ${page.url()} — consent may have been auto-granted (skip_consent=true)`,
    );
  }
});
