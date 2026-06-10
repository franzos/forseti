// SAML SSO end-to-end against the playground's Jackson + mock-saml pair
// (`--profile saml` services in infra/docker-compose.yml).
//
// Serial bucket: scenario 1 creates the connection scenarios 2 and 3
// ride. The suite is self-healing — a connection left behind by a
// previous run is deleted before re-creating, so reruns against shared
// state stay green.
//
// Chain under test (scenario 2): /sso/default → Jackson authorize
// (127.0.0.1:5225) → mock-saml sign-in (127.0.0.1:4480) → SAMLResponse →
// Jackson ACS → /sso/callback (code exchange + JIT identity) → Kratos
// recovery-link redemption → dashboard with a native session. Everything
// is browser-reachable because the Playwright container runs with
// `--network host` (see Makefile).
//
// Requires: active license with the `saml` feature activated via
// /admin/license, [saml] configured, and the admin env vars (skips
// without them, mirroring the unlicensed admin specs).
//
// Coverage notes — two resolve_identity fail-closed branches are NOT
// covered here because they're unreachable through this playground:
//
//   * `missing_email` (empty asserted email): mock-saml never asserts an
//     empty NameID/email. Leaving its `username` field blank doesn't yield
//     an empty subject — the IdP substitutes its built-in default test user
//     (`<default>@example.com`), so the empty-email guard is structurally
//     unreachable via the browser. Left to code review.
//   * `email_conflict` (409 the verified-lookup missed): only reachable by
//     staging a Kratos identity that `admin_find_identity_by_email`
//     (credentials_identifier filter) misses yet `create_identity` 409s on.
//     The integration test `kratos_jit_assumptions_hold` already pins that
//     a verifiable-address-only identity IS surfaced by that lookup and that
//     a duplicate create 409s — i.e. the lookup catches the conflict first,
//     so there's no clean state that misses the lookup but conflicts the
//     create. Compounding it, the full flow needs mock-saml to assert the
//     conflicting address, and mock-saml only emits `username@example.com`.
//     Not cleanly stageable; left to code review.
import { test, expect, type Page } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { registerUser, logout, uniqueEmail } from '../../helpers/register';

// Jackson 26.x only accepts localhost/HTTPS metadata URLs, which rules
// out `http://mock-saml:4000/...` (container-network, plain HTTP) — so
// the test fetches the IdP metadata itself via the published host port
// and pastes the raw XML instead.
const IDP_METADATA_FETCH_URL = 'http://127.0.0.1:4480/api/saml/metadata';
const CONNECTION_NAME = 'Mock SAML';

// Shared across the serial JIT-create + durable-relogin scenarios: the
// first login provisions this address, the second re-resolves it.
const JIT_EMAIL = `saml-e2e-${Date.now()}@example.com`;

/**
 * Drive mock-saml's sign-in page: a `username` local-part input plus a
 * domain `<select id="domain">` with options example.com / example.org.
 * Any password works. Caller must already be on (or navigating toward)
 * the mock-saml page.
 */
async function signInAtMockSaml(page: Page, email: string): Promise<void> {
  const [local, domain] = email.split('@');
  expect(domain).toBe('example.com'); // mock-saml's domain select only offers example.com/org
  const username = page.locator('input#username');
  await username.waitFor({ state: 'visible', timeout: 30_000 });
  await username.fill(local);
  // Explicitly select the email's domain — don't rely on the default.
  await page.locator('select#domain').selectOption(domain);
  await page.locator('button:has-text("Sign In")').click();
}

/**
 * Create a Mock SAML connection for the org whose dropdown label matches
 * `orgLabel` (rendered as `"<name> (<slug>)"` in the admin select). Pastes
 * the raw IdP metadata XML — same path the default-org scenario uses, but
 * driven by org label so it works for UUID-keyed non-default orgs too.
 * Caller must already be signed in as admin (AAL2).
 */
async function createSamlConnection(
  page: Page,
  orgLabel: string,
  displayName: string,
  metadataUrl: string = IDP_METADATA_FETCH_URL,
): Promise<void> {
  const metadataResponse = await page.request.get(metadataUrl);
  expect(
    metadataResponse.ok(),
    `mock-saml not reachable at ${metadataUrl} — is the saml profile up? (make stack-up-saml)`,
  ).toBe(true);
  const metadataXml = await metadataResponse.text();
  expect(metadataXml).toContain('EntityDescriptor');

  await page.goto('/admin/saml/new');
  await page.locator('select[name="org_id"]').selectOption({ label: orgLabel });
  await page.locator('input[name="display_name"]').fill(displayName);
  await page.locator('textarea[name="metadata_xml"]').fill(metadataXml);
  await page.locator('button:has-text("Create connection")').click();
  await page.waitForURL((u) => u.pathname === '/admin/saml', { timeout: 30_000 });
}

test.describe.serial('SAML SSO via Jackson + mock-saml', () => {
  test('admin creates the Mock SAML connection for the default org', async ({ page }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    await signInAdminAal2(page, creds!);

    // Self-heal: a previous run leaves its connection behind (one per
    // org). Delete it via the UI so the create below starts clean.
    await page.goto('/admin/saml');
    const deleteLink = page.locator('a[href="/admin/saml/default/delete"]');
    if ((await deleteLink.count()) > 0) {
      await deleteLink.click();
      await page.locator('button:has-text("Delete connection")').click();
      await page.waitForURL((u) => u.pathname === '/admin/saml', { timeout: 15_000 });
    }

    await createSamlConnection(page, 'Default (default)', CONNECTION_NAME);

    const row = page.locator('tbody tr', { hasText: CONNECTION_NAME });
    await expect(row).toContainText('Default');
    await expect(row).toContainText('Enabled');
  });

  test('JIT SSO login lands on the dashboard with a session', async ({ page }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    // Fresh address → exercises the JIT-create path (no existing
    // identity, no saml_links row).
    const email = JIT_EMAIL;

    await page.goto('/sso/default');
    await signInAtMockSaml(page, email);

    // mock-saml POSTs the SAMLResponse to Jackson's ACS, Jackson 302s to
    // /sso/callback, the portal redeems a Kratos recovery link and the
    // post-recovery interception bounces the arrival to `/`. Generous
    // timeout: four services round-trip plus assertion signing.
    await page.waitForURL((u) => u.pathname === '/', { timeout: 60_000 });

    // Signed in: the header chrome shows the session's email.
    await expect(page.getByText(email).first()).toBeVisible();
  });

  test('repeat SSO login for the same address re-lands on the dashboard', async ({
    page,
    context,
  }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    // Same address as the JIT test above: first login created the
    // saml_links row (subject backfilled), so this re-login resolves via
    // the durable subject path. mock-saml emits a stable subject —
    // `sha256(email)` (its `id` attribute, surfaced by Jackson as the
    // profile id) — so db::link_subject matches on re-login, exactly the
    // mechanism a stable-NameID IdP drives.
    const email = JIT_EMAIL;

    // Fresh context: no carried-over session — a genuine second sign-in.
    await context.clearCookies();
    await page.goto('/sso/default');
    await signInAtMockSaml(page, email);

    await page.waitForURL((u) => u.pathname === '/', { timeout: 60_000 });
    await expect(page.getByText(email).first()).toBeVisible();
  });

  test('SSO is blocked for an existing identity with an unverified email', async ({ page }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    // Register through the normal UI and deliberately skip verification —
    // the address stays unverified on the Kratos identity.
    const user = await registerUser(page, 'saml-blocked');
    await logout(page);

    await page.goto('/sso/default');
    await signInAtMockSaml(page, user.email);

    // The callback resolves the email to the unverified identity and
    // fails closed to the blocked page instead of minting a session.
    await expect(page.getByText("We couldn't sign you in")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(user.email)).toBeVisible();
  });

  test('admin kill switch + duplicate-connection rejection on the default org', async ({
    page,
  }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    await signInAdminAal2(page, creds!);

    // (a) Kill switch: disable the default connection and confirm the row
    // flips to Disabled and /sso/default now serves the neutral
    // unavailable page (no Jackson redirect) — a disabled connection is
    // indistinguishable from no connection, by design.
    await page.goto('/admin/saml');
    const row = page.locator('tbody tr', { hasText: CONNECTION_NAME });
    await expect(row).toContainText('Enabled');
    await row.locator('button:has-text("Disable")').click();
    await page.waitForURL((u) => u.pathname === '/admin/saml', { timeout: 15_000 });
    await expect(page.locator('tbody tr', { hasText: CONNECTION_NAME })).toContainText('Disabled');

    await page.goto('/sso/default');
    // Neutral page, not a Jackson authorize redirect: stays on /sso/default
    // and renders the uniform unavailable copy.
    await expect(page).toHaveURL(/\/sso\/default$/);
    await expect(page.getByText('Single sign-on unavailable')).toBeVisible();

    // Re-enable so the connection is back for reruns and any later scenario.
    await page.goto('/admin/saml');
    await page.locator('tbody tr', { hasText: CONNECTION_NAME }).locator('button:has-text("Enable")').click();
    await page.waitForURL((u) => u.pathname === '/admin/saml', { timeout: 15_000 });
    await expect(page.locator('tbody tr', { hasText: CONNECTION_NAME })).toContainText('Enabled');

    // (b) Duplicate rejection: a second connection for the default org must
    // be refused — one connection per org.
    await page.goto('/admin/saml/new');
    await page.locator('select[name="org_id"]').selectOption('default');
    await page.locator('input[name="display_name"]').fill('Duplicate Mock SAML');
    // Any non-empty metadata satisfies the "exactly one source" check; the
    // duplicate guard fires before Jackson is touched.
    await page.locator('textarea[name="metadata_xml"]').fill('<dummy/>');
    await page.locator('button:has-text("Create connection")').click();
    // Stays on the new-connection page with the rejection copy.
    await expect(page.getByText('That organization already has a connection.')).toBeVisible({
      timeout: 15_000,
    });
  });

  // GAP 1 — the headline multi-tenant guarantee: an identity that is
  // verified and a member of org A, asserted by org B's SSO where it is NOT
  // a member, must be blocked AND must NOT get a session. The block is only
  // reachable for a NON-default org: the orgs middleware auto-joins every
  // session into Default, so `find_member` is always Some there.
  test('cross-org SSO is blocked with no session minted for a non-member org', async ({
    page,
    context,
    request,
  }) => {
    const creds = adminCredsFromEnv();
    test.skip(
      !creds,
      'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the SAML admin scenario',
    );

    // A non-default org "acme-<ts>" with its own Mock SAML connection.
    // Created by the admin (who becomes its owner) — the SSO user below is
    // deliberately NOT a member.
    const orgSlug = `acme-${Date.now()}`;
    const orgName = `Acme ${Date.now()}`;

    await signInAdminAal2(page, creds!);

    // Create the org via the multi-org settings form (licensed feature).
    await page.goto('/settings/organizations');
    await page.locator('input[name="name"]').fill(orgName);
    await page.locator('input[name="slug"]').fill(orgSlug);
    await page.locator('form button[type="submit"]:has-text("Create")').click();
    await page.waitForURL((u) => u.pathname === `/settings/organizations/${orgSlug}`, {
      timeout: 15_000,
    });

    // Its own connection. Jackson keys connections by the IdP entityID and
    // refuses to register the same one under two tenants, so reuse mock-saml's
    // namespace feature — `/api/namespace/<ns>/...` yields a distinct
    // entityID (`.../entityid/<ns>`). Use the timestamped slug as the
    // namespace so reruns get a fresh entityID and don't collide in Jackson.
    // Display name deliberately avoids the "Mock SAML" substring so the
    // default-org scenario's `hasText: 'Mock SAML'` row locator can't match
    // this connection if cleanup is ever skipped.
    const acmeConnName = 'Acme SSO';
    const acmeMetadataUrl = `http://127.0.0.1:4480/api/namespace/${orgSlug}/saml/metadata`;
    await createSamlConnection(page, `${orgName} (${orgSlug})`, acmeConnName, acmeMetadataUrl);

    // Provision a VERIFIED identity that is a member of Default only, via a
    // fresh JIT login on /sso/default. (JIT creates a verified Kratos
    // identity and joins Default — exactly the member-of-A-only shape.)
    const email = uniqueEmail('saml-xorg');
    await context.clearCookies();
    await page.goto('/sso/default');
    await signInAtMockSaml(page, email);
    await page.waitForURL((u) => u.pathname === '/', { timeout: 60_000 });
    await expect(page.getByText(email).first()).toBeVisible();

    // Fresh browser: drop the Default session so the cross-org attempt
    // starts unauthenticated — the block must hold without a pre-session.
    await context.clearCookies();

    // Attempt SSO into Acme as that Default-only member.
    await page.goto(`/sso/${orgSlug}`);
    await signInAtMockSaml(page, email);

    // Cross-org block copy (saml_blocked.html CrossOrgNotMember branch).
    await expect(page.getByText("We couldn't sign you in")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(/isn't a member of this organization/)).toBeVisible();

    // Security-load-bearing: NO session was minted. Three checks:
    //  1. Kratos whoami in this browser context is 401 (no native session).
    const cookies = await context.cookies();
    const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
    const whoami = await request.get('http://localhost:4433/sessions/whoami', {
      headers: cookieHeader ? { cookie: cookieHeader } : {},
    });
    expect(whoami.status(), 'cross-org block must not establish a Kratos session').toBe(401);

    //  2. The dashboard bounces to /login (RequireSession, unauthenticated).
    await page.goto('/');
    await page.waitForURL((u) => u.pathname.startsWith('/login'), { timeout: 15_000 });
    await expect(page).toHaveURL(/\/login/);

    //  3. The header chrome does not surface the asserted email anywhere.
    await expect(page.getByText(email)).toHaveCount(0);

    // Clean up the Acme connection so it doesn't leak into the default-org
    // scenario's row locator on the next run (the org row itself is inert).
    await context.clearCookies();
    await signInAdminAal2(page, creds!);
    await page.goto('/admin/saml');
    const acmeRow = page.locator('tbody tr', { hasText: acmeConnName });
    if ((await acmeRow.count()) > 0) {
      await acmeRow.locator('a:has-text("Delete")').click();
      await page.locator('button:has-text("Delete connection")').click();
      await page.waitForURL((u) => u.pathname === '/admin/saml', { timeout: 15_000 });
    }
  });
});
