// Scenario F (licensed): host enrollment is org-scoped, and a host's org is
// immutable.
//
// Enrolling a host against a non-default org, scoped to that org's team,
// proves the org picker + team-checkbox grouping work end to end. The edit
// page then proves the two invariants the Rust handler enforces but only the
// rendered form surfaces: the org is read-only (no select), and the team
// checkboxes follow the host's own org — a team from a different org never
// appears as a scope option.
//
// Needs admin creds + an active orgs license; skips without creds. Host
// enrollment itself isn't feature-gated, but creating the named org + teams is.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { createOrg, createTeam } from '../../helpers/orgs';
import { enrollHost } from '../../helpers/posix';

const TEAMS = '/settings/organization/teams';

test('host enroll picks a non-default org; edit keeps org fixed + teams org-scoped', async ({
  page,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the host enroll scenario');

  await signInAdminAal2(page, creds!);
  page.on('dialog', (d) => d.accept());

  const stamp = Date.now();
  const orgName = `Hostsorg ${stamp}`;
  const teamName = `Fleet ${stamp}`;
  const hostname = `host-${stamp}.example.com`;

  // A Default-org team that must NOT appear on a different org's host edit.
  const otherTeam = await createTeam(page, `Other ${stamp}`);

  // The named org + its team, which the host will be scoped to.
  const slug = await createOrg(page, orgName, `hostsorg-${stamp}`);
  const team = await createTeam(page, teamName, slug);

  try {
    const { hostId } = await enrollHost(page, { hostname, orgLabel: orgName, teamIds: [team] });

    // The list shows the host scoped to the named org's team.
    await page.goto('/admin/hosts');
    await expect(page.locator('tr', { hasText: hostname })).toContainText(teamName);

    // Edit: org is read-only (no select), shown as text.
    await page.goto(`/admin/hosts/${hostId}/edit`);
    await expect(page.locator('select[name="org_id"]')).toHaveCount(0);
    await expect(page.getByText(orgName, { exact: false })).toBeVisible();

    // Team options follow the host's org: its own team is present + checked;
    // the Default-org team is not an option here.
    await expect(page.locator(`input[name="team_ids"][value="${team}"]`)).toBeChecked();
    await expect(page.locator(`input[name="team_ids"][value="${otherTeam}"]`)).toHaveCount(0);
  } finally {
    // Drop the Default-org team so the shared org is left clean.
    await page.goto(TEAMS);
    const del = page.locator(`form[action="${TEAMS}/${otherTeam}/delete"]`);
    if ((await del.count()) > 0) {
      await Promise.all([
        page.waitForResponse(
          (r) => r.url().includes(`/teams/${otherTeam}/delete`) && r.request().method() === 'POST',
          { timeout: 15_000 },
        ),
        del.locator('button[type="submit"]').click(),
      ]);
    }
  }
});
