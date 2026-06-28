// Scenario E (licensed): the profile page audiences teams and hosts apart.
//
// On /users/{id}:
//   - the subject (self) sees their teams AND their reachable Linux hosts;
//   - a non-admin ORG OWNER sees teams but must NOT see hosts (the host list
//     is an enumeration oracle, fenced to self/admin only);
//   - the AAL2 admin sees both.
// This three-way audience split (self vs. owner vs. admin) is invisible to the
// Rust tests, which can't render the per-viewer page. Needs an org member with
// a POSIX account in a team, plus a host scoped to that team.
//
// Needs admin creds + an active orgs + linux_auth license; skips without
// creds. (CI currently mints orgs + saml only — linux_auth must be in the
// activated blob for the host assertions to hold.)
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { uniqueEmail } from '../../helpers/register';
import { createOrg, createTeam, addTeamMember, inviteAndAccept } from '../../helpers/orgs';
import { provisionAccount, enrollHost } from '../../helpers/posix';

test('profile shows teams to self/owner/admin but hosts to self/admin only', async ({
  page,
  browser,
  request,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the profile teams/hosts scenario');

  await signInAdminAal2(page, creds!);

  const stamp = Date.now();
  const orgName = `Hosts ${stamp}`;
  const teamName = `Ops ${stamp}`;
  const hostname = `web-${stamp}.example.com`;
  const slug = await createOrg(page, orgName, `hosts-${stamp}`);

  // Subject U (member) and a non-admin owner O of the same org.
  const subject = await inviteAndAccept(page, browser, request, {
    email: uniqueEmail('playwright-ph-subject'),
    role: 'member',
    slug,
  });
  const owner = await inviteAndAccept(page, browser, request, {
    email: uniqueEmail('playwright-ph-owner'),
    role: 'owner',
    slug,
  });

  try {
    // U gets a POSIX account, joins a team, and a host is scoped to that team.
    await provisionAccount(page, subject.identityId, `phuser${stamp}`);
    const team = await createTeam(page, teamName, slug);
    await addTeamMember(page, team, subject.identityId, slug);
    await enrollHost(page, { hostname, orgLabel: orgName, teamIds: [team] });

    const profile = `/users/${subject.identityId}`;

    // Self: teams + hosts.
    await subject.page.goto(profile);
    await expect(subject.page.locator('article')).toContainText(teamName);
    await expect(subject.page.locator('article')).toContainText(hostname);

    // Non-admin owner: teams, but NO hosts section at all.
    await owner.page.goto(profile);
    await expect(owner.page.locator('article')).toContainText(teamName);
    await expect(owner.page.locator('h2', { hasText: 'Linux hosts' })).toHaveCount(0);
    await expect(owner.page.locator('article')).not.toContainText(hostname);

    // AAL2 admin: teams + hosts.
    await page.goto(profile);
    await expect(page.locator('article')).toContainText(teamName);
    await expect(page.locator('article')).toContainText(hostname);
  } finally {
    await subject.context.close();
    await owner.context.close();
  }
});
