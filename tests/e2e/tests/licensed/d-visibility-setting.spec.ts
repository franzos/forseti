// Scenario D (licensed): directory-visibility policy drives both the roster
// and the public profile, and a restrictive shared org never leaks as a chip.
//
// On a fresh named org the owner walks all -> admins_only -> same_group. A
// plain member's view of a peer changes in lockstep: visible under `all`,
// gone under `admins_only` (and the peer's /users/{id} 404s), back under
// `same_group` once they share a team. The chip guarantee is the subtle bit:
// the peer is also a co-member of the admins_only Default org, where they're
// hidden — so the named-org profile must show the named-org chip but NOT the
// Default chip (chips derive from visible orgs only, never the raw overlap).
//
// Needs admin creds + an active orgs license; skips without creds.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { uniqueEmail } from '../../helpers/register';
import {
  createOrg,
  createTeam,
  addTeamMember,
  setVisibility,
  inviteAndAccept,
  orgBase,
} from '../../helpers/orgs';

test('visibility policy gates roster + profile, no restrictive-org chip leak', async ({
  page,
  browser,
  request,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the visibility scenario');

  await signInAdminAal2(page, creds!);
  page.on('dialog', (d) => d.accept());

  const stamp = Date.now();
  const orgName = `Vis ${stamp}`;
  const slug = await createOrg(page, orgName, `vis-${stamp}`);
  const membersPath = `${orgBase(slug)}/members`;

  // Two members of the named org (and, via registration, of Default too).
  const emailN = uniqueEmail('playwright-vis-n');
  const emailM = uniqueEmail('playwright-vis-m');
  const n = await inviteAndAccept(page, browser, request, { email: emailN, role: 'member', slug });
  await n.context.close(); // N only needs to exist + be team-scoped
  const m = await inviteAndAccept(page, browser, request, { email: emailM, role: 'member', slug });
  const pageM = m.page;

  try {
    // Co-team in the named org, so same_group will make them mutually visible.
    const team = await createTeam(page, `Tv ${stamp}`, slug);
    await addTeamMember(page, team, m.identityId, slug);
    await addTeamMember(page, team, n.identityId, slug);

    // all: M sees N; N's profile is viewable.
    expect((await setVisibility(page, 'all', slug)).status()).toBe(303);
    await pageM.goto(membersPath);
    expect((await pageM.locator('body').innerText()).toLowerCase()).toContain(emailN.toLowerCase());
    expect((await pageM.goto(`/users/${n.identityId}`))?.status()).toBe(200);

    // admins_only: N drops off M's roster and N's profile 404s (hidden in
    // both shared orgs, so no visible org remains).
    expect((await setVisibility(page, 'admins_only', slug)).status()).toBe(303);
    await pageM.goto(membersPath);
    expect((await pageM.locator('body').innerText()).toLowerCase()).not.toContain(
      emailN.toLowerCase(),
    );
    expect((await pageM.goto(`/users/${n.identityId}`))?.status()).toBe(404);

    // same_group: co-team makes N visible again — roster + profile — and the
    // profile chips show the named org but NOT the restrictive Default org.
    expect((await setVisibility(page, 'same_group', slug)).status()).toBe(303);
    await pageM.goto(membersPath);
    expect((await pageM.locator('body').innerText()).toLowerCase()).toContain(emailN.toLowerCase());
    expect((await pageM.goto(`/users/${n.identityId}`))?.status()).toBe(200);
    const article = pageM.locator('article');
    await expect(article).toContainText(orgName);
    await expect(article).not.toContainText('Default');
  } finally {
    await m.context.close();
  }
});
