// Scenario G: self-delete confirm page (lists granted apps, requires
// typing email to confirm) + actual delete.
//
// The Rust suite covers the outbox saga (`tests/integration/
// bug_regressions.rs` and the webhook test module). What's NOT covered
// there is the rendered confirm page itself — specifically that:
//   (a) the consent-granted client's display name appears in the
//       "THESE APPS WILL BE TOLD YOU'RE GONE" card
//   (b) the form REQUIRES typing the email (HTML5 `required` + server-
//       side equality check, both observed)
//   (c) submitting the right value clears the session, redirects to
//       /login, and the identity actually goes from Kratos.
//
// Skips when admin env vars aren't set.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { logout, registerUser } from '../../helpers/register';
import { createOAuthClient } from '../../helpers/clients';
import { generatePkcePair } from '../../helpers/oauth';

const HYDRA_AUTHORIZE = 'http://host.containers.internal:4444/oauth2/auth';
const KRATOS_PUBLIC = 'http://host.containers.internal:4433';
const KRATOS_ADMIN = 'http://host.containers.internal:4434';

const REDIRECT_URI = 'http://localhost:9876/cb';

test('self-delete confirm page lists granted apps, enforces email confirm, and deletes', async ({
  page,
  request,
}) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the self-delete confirm scenario',
  );

  // 1. Admin creates an OAuth client with a recognisable name + a
  //    portal-namespaced `account_deletion_url` so it shows up in the
  //    "apps to notify" card.
  await signInAdminAal2(page, adminCreds!);
  const clientDisplayName = `Playwright Self-Delete Test ${Date.now()}`;
  const { clientId } = await createOAuthClient(page, {
    name: clientDisplayName,
    redirectUri: REDIRECT_URI,
    accountDeletionUrl: 'https://httpbin.org/anything',
  });

  // 2. Logout admin, register a fresh end-user, run the OAuth
  //    authorize → consent flow so a Hydra consent session lands on
  //    the user's subject.
  await logout(page);
  const endUser = await registerUser(page, 'playwright-selfdelete-user');

  const pkce = generatePkcePair();
  const authUrl = new URL(HYDRA_AUTHORIZE);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid email profile offline_access');
  authUrl.searchParams.set('state', `e2e-${Date.now()}`);
  authUrl.searchParams.set('code_challenge', pkce.challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  await page.goto(authUrl.toString());
  await page.waitForURL(
    (u) => u.pathname === '/oauth/consent' || u.host.startsWith('localhost:9876'),
  );

  // Click Allow — we don't need the token, just the consent grant
  // landing in Hydra. Wait for the callback request, ignoring the
  // ERR_CONNECTION_REFUSED that follows.
  const navPromise = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI));
  await page
    .locator('form[action="/oauth/consent"] button[name="decision"][value="accept"]')
    .click();
  await navPromise;

  // 3. Navigate to /settings/account/delete. This handler is gated by
  //    the privileged-session window (`fetch_settings_subpage` ↔
  //    `privileged_session_max_age: 15m`). We're well inside that
  //    window — registration counts as a fresh login.
  await page.goto('/settings/account/delete');
  // The privileged gate may redirect to /login?refresh=true if Kratos
  // thinks the session needs re-auth. Follow the chain — if it bounces,
  // re-submit the password and come back.
  if (page.url().includes('/login')) {
    await page.locator('input[name="password"]').fill(endUser.password);
    await page.locator('button[name="method"][value="password"]').click();
    await page.waitForURL((u) => u.pathname.startsWith('/settings/account/delete'), {
      timeout: 15_000,
    });
  }
  expect(page.url()).toMatch(/\/settings\/account\/delete\?flow=/);

  // 4. Assert: the OAuth client's display name renders in the apps-to-
  //    notify card. The template's heading is "THESE APPS WILL BE TOLD
  //    YOU'RE GONE"; the client name is rendered as a `<li>` immediately
  //    after.
  await expect(page.getByText(clientDisplayName)).toBeVisible();

  // 5. Assert: the confirm_email input is present + required.
  const confirmInput = page.locator('input[name="confirm_email"]');
  await expect(confirmInput).toBeVisible();
  await expect(confirmInput).toHaveAttribute('required', '');
  await expect(confirmInput).toHaveAttribute('type', 'email');

  // 6. Submitting empty: the browser's HTML5 validity blocks the submit
  //    entirely — no network request fires. Confirm by checking that
  //    `validity.valid` is false on the input after a submit attempt.
  await page.locator('form[action^="/settings/account/delete"] button[type="submit"]').click();
  const isValid = await confirmInput.evaluate((el) => (el as HTMLInputElement).validity.valid);
  expect(isValid).toBe(false);
  // URL didn't change.
  expect(page.url()).toMatch(/\/settings\/account\/delete\?flow=/);

  // 7. Type the WRONG email + submit. Server-side equality check (the
  //    handler does `eq_ignore_ascii_case`) redirects back to the
  //    confirm page without deleting anything.
  await confirmInput.fill(`wrong-${endUser.email}`);
  await Promise.all([
    page.waitForURL(/\/settings\/account\/delete/, { timeout: 15_000 }),
    page.locator('form[action^="/settings/account/delete"] button[type="submit"]').click(),
  ]);
  // Identity must still exist.
  const stillThere = await request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(endUser.email)}`,
  );
  expect(stillThere.ok()).toBeTruthy();
  expect(((await stillThere.json()) as Array<unknown>).length).toBe(1);

  // 8. Type the CORRECT email + submit. The saga writes outbox rows,
  //    deletes the Kratos identity, clears `ory_kratos_session`, and
  //    303s to /login?msg=account_deleted.
  await page.goto('/settings/account/delete');
  // Privileged gate again — the wrong-email submit may have aged the
  // window or thrown us through a new flow. Re-prove if needed.
  if (page.url().includes('/login')) {
    await page.locator('input[name="password"]').fill(endUser.password);
    await page.locator('button[name="method"][value="password"]').click();
    await page.waitForURL((u) => u.pathname.startsWith('/settings/account/delete'), {
      timeout: 15_000,
    });
  }
  await page.locator('input[name="confirm_email"]').fill(endUser.email);
  await Promise.all([
    page.waitForURL((u) => u.pathname.startsWith('/login'), { timeout: 20_000 }),
    page.locator('form[action^="/settings/account/delete"] button[type="submit"]').click(),
  ]);

  // 9. Assert: the Kratos identity is gone from the admin index.
  //    Kratos may take a moment to surface the deletion to the
  //    admin index after the delete API returns — poll briefly.
  const deadline = Date.now() + 5000;
  let identityGone = false;
  while (Date.now() < deadline) {
    const lookup = await request.get(
      `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(endUser.email)}`,
    );
    if (lookup.ok()) {
      const arr = (await lookup.json()) as Array<unknown>;
      if (arr.length === 0) {
        identityGone = true;
        break;
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  expect(identityGone, `Kratos identity for ${endUser.email} should be gone`).toBe(true);

  // 10. Assert: whoami with the surviving cookie jar returns 401 (the
  //     portal cleared `ory_kratos_session`, and even if the cookie
  //     stuck Kratos drops the session server-side on identity delete).
  const cookies = await page.context().cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  const whoami = await request.get(`${KRATOS_PUBLIC}/sessions/whoami`, {
    headers: { cookie: cookieHeader },
    failOnStatusCode: false,
  });
  expect(whoami.status()).toBe(401);
});
