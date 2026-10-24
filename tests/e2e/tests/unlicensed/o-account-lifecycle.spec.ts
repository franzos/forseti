// Scenario O: account lifecycle from the settings page — the export
// download, the delete confirm page's cards, the completed deletion, and
// the admin-side delete confirm text.
//
// The Rust suite (`tests/integration/account_export.rs`,
// `account_delete.rs`) covers the envelope contents and the deletion
// saga. What's only observable in a browser:
//   (a) the export link ends in a real file download after the Kratos
//       settings-flow redirect chain
//   (b) the confirm page renders the apps card and the "What we keep" card
//   (c) the completed deletion lands on the signed-out page with no
//       `ory_kratos_session` left in the cookie jar
//   (d) the admin confirm page spells out what is removed and what stays
//
// Scenario G already covers the apps card with a consent-granted client;
// this spec asserts the empty state. The admin part skips when the admin
// env vars aren't set.
import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { registerUser, logout } from '../../helpers/register';

const KRATOS_ADMIN = 'http://host.containers.internal:4434';

const TOP_LEVEL_KEYS = [
  'format',
  'format_version',
  'product',
  'exported_at',
  'account',
  'identities',
  'sessions',
  'billing',
  'audit',
  'data',
];

/** Re-prove the password if the privileged-session gate bounced to /login. */
async function passPrivilegedGate(page: import('@playwright/test').Page, password: string, target: string) {
  if (page.url().includes('/login')) {
    await page.locator('input[name="password"]').fill(password);
    await page.locator('button[name="method"][value="password"]').click();
    await page.waitForURL((u) => u.pathname.startsWith(target), { timeout: 15_000 });
  }
}

test('export downloads a parseable envelope, confirm page shows both cards, deletion signs out', async ({
  page,
}) => {
  const user = await registerUser(page, 'playwright-lifecycle-user');

  // 1. Export: the link goes through the Kratos settings-flow init and
  //    comes back as an attachment.
  await page.goto('/settings/account');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('a[href="/settings/account/export"]').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^forseti-export-\d{4}-\d{2}-\d{2}\.json$/);
  const savedPath = test.info().outputPath('export.json');
  await download.saveAs(savedPath);
  const envelope = JSON.parse(await readFile(savedPath, 'utf8')) as Record<string, unknown>;
  expect(envelope.format).toBe('gofranz-account-export');
  expect(envelope.format_version).toBe(1);
  expect(envelope.product).toBe('forseti');
  for (const key of TOP_LEVEL_KEYS) {
    expect(envelope, `top-level key ${key}`).toHaveProperty(key);
  }
  expect((envelope.account as { traits: { email: string } }).traits.email).toBe(user.email);

  // 2. Confirm page: empty apps card plus the "What we keep" card with the
  //    retention days substituted.
  await page.goto('/settings/account/delete');
  await passPrivilegedGate(page, user.password, '/settings/account/delete');
  expect(page.url()).toMatch(/\/settings\/account\/delete\?flow=/);
  await expect(page.getByText('No third-party apps have copies of your data')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What we keep' })).toBeVisible();
  await expect(page.getByText(/Audit entries that name your account stay for \d+ days/)).toBeVisible();
  await expect(
    page.getByText('Organizations, teams, hosts and domains you created stay, with your name removed.'),
  ).toBeVisible();

  // 3. Delete: typed email, land on /login, cookie jar without the Kratos
  //    session.
  await page.locator('input[name="confirm_email"]').fill(user.email);
  await Promise.all([
    page.waitForURL((u) => u.pathname.startsWith('/login'), { timeout: 20_000 }),
    page.locator('form[action^="/settings/account/delete"] button[type="submit"]').click(),
  ]);
  await expect(page.locator('input[name="identifier"]')).toBeVisible();
  const cookies = await page.context().cookies();
  expect(cookies.map((c) => c.name)).not.toContain('ory_kratos_session');

  const lookup = await page.request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(user.email)}`,
  );
  expect(lookup.ok()).toBeTruthy();
  expect(((await lookup.json()) as Array<unknown>).length).toBe(0);
});

test('admin delete confirm page lists what is removed and what stays', async ({ page }) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the admin delete confirm scenario',
  );

  const target = await registerUser(page, 'playwright-lifecycle-target');
  const res = await page.request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(target.email)}`,
  );
  const targetId = ((await res.json()) as Array<{ id: string }>)[0]?.id;
  expect(targetId, `no identity for ${target.email}`).toBeTruthy();
  await logout(page);

  await signInAdminAal2(page, adminCreds!);
  await page.goto(`/admin/identities/${targetId}`);
  await page.locator(`a[href="/admin/identities/${targetId}/delete"]`).click();
  await page.waitForURL((u) => u.pathname === `/admin/identities/${targetId}/delete`);

  await expect(page.getByRole('heading', { name: `Delete identity ${targetId}?` })).toBeVisible();
  const body = page.locator('h1 + p');
  await expect(body).toContainText(
    'credentials, sessions, 2FA and recovery codes, profile and username, linked providers, SSH keys, POSIX account, offline passphrase, organization and team memberships, and invites to its email',
  );
  await expect(body).toContainText('Apps holding a copy of the data are told to delete it.');
  await expect(body).toContainText(
    'Audit entries stay for the retention period; organizations, teams, hosts and domains it created stay with the name removed.',
  );
  await expect(page.locator('input[name="confirm"][value="yes"]')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Delete identity' })).toBeVisible();
});
