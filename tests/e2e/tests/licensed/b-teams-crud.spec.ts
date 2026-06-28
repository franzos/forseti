// Scenario B (licensed): full team lifecycle on the Default org.
//
// With an active Organizations license the teams surface stops being an
// upsell and becomes a working CRUD page. As the Default org owner (admin),
// create a team, rename it, add two members, remove one, then delete it. The
// members auto-join Default, so this needs no invites. Drives every mutating
// form through the rendered DOM (CSRF cookie + hidden field together).
//
// Needs admin creds + an active orgs license; skips without creds.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { registerUser } from '../../helpers/register';
import { createTeam, addTeamMember, lookupIdentityId } from '../../helpers/orgs';

const TEAMS = '/settings/organization/teams';

test('owner creates, renames, populates, prunes, and deletes a team', async ({
  page,
  browser,
  request,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the teams CRUD scenario');

  // Two members that auto-join Default on registration. Separate contexts so
  // their sessions don't bleed into each other or the admin.
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  let emailA = '';
  let emailB = '';
  try {
    emailA = (await registerUser(await ctxA.newPage(), 'playwright-team-a')).email;
    emailB = (await registerUser(await ctxB.newPage(), 'playwright-team-b')).email;
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
  const idA = await lookupIdentityId(request, emailA);
  const idB = await lookupIdentityId(request, emailB);

  await signInAdminAal2(page, creds!);
  page.on('dialog', (d) => d.accept()); // team delete confirms via window.confirm

  const stamp = Date.now();
  const name = `Crew ${stamp}`;
  const renamed = `Squad ${stamp}`;

  // Create.
  const teamId = await createTeam(page, name);
  await page.goto(TEAMS);
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/rename"] input[name="name"]`)).toHaveValue(
    name,
  );

  // Rename.
  const renameForm = page.locator(`form[action="${TEAMS}/${teamId}/rename"]`);
  await renameForm.locator('input[name="name"]').fill(renamed);
  await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes(`/teams/${teamId}/rename`) && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    renameForm.locator('button[type="submit"]').click(),
  ]);
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/rename"] input[name="name"]`)).toHaveValue(
    renamed,
  );

  // Add both members; both now have a roster remove-form (membership proof
  // that survives the addable-select reshuffle).
  await addTeamMember(page, teamId, idA);
  await addTeamMember(page, teamId, idB);
  await page.goto(`${TEAMS}?team=${teamId}`);
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/members/${idA}/remove"]`)).toBeVisible();
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/members/${idB}/remove"]`)).toBeVisible();

  // Remove A; only B remains.
  const removeA = page.locator(`form[action="${TEAMS}/${teamId}/members/${idA}/remove"]`);
  await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes(`/members/${idA}/remove`) && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    removeA.locator('button[type="submit"]').click(),
  ]);
  await page.goto(`${TEAMS}?team=${teamId}`);
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/members/${idB}/remove"]`)).toBeVisible();
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/members/${idA}/remove"]`)).toHaveCount(0);

  // Delete the team; its row disappears.
  await page.goto(TEAMS);
  const deleteForm = page.locator(`form[action="${TEAMS}/${teamId}/delete"]`);
  await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes(`/teams/${teamId}/delete`) && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    deleteForm.locator('button[type="submit"]').click(),
  ]);
  await expect(page.locator(`form[action="${TEAMS}/${teamId}/rename"]`)).toHaveCount(0);
});
