// Scenario C (licensed): same-group directory visibility on the Default org.
//
// Proves the headline same-group guarantees end to end:
//   1. the guardrail — you can't switch to same_group with no team yet (400);
//   2. a plain member sees co-team peers but NOT members of other teams, both
//      on the members roster AND on the public /users/{id} view (404 for a
//      non-co-team peer, the no-status-oracle path).
// The visibility predicate is unit-tested in Rust; only a browser proves the
// rendered roster and the per-viewer profile gate honour it together.
//
// Needs admin creds + an active orgs license; skips without creds. Mutates the
// shared Default org and restores admins_only + deletes its teams at the end.
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { registerUser } from '../../helpers/register';
import { createTeam, addTeamMember, setVisibility, lookupIdentityId } from '../../helpers/orgs';

const MEMBERS = '/settings/organization/members';
const TEAMS = '/settings/organization/teams';

async function deleteAllTeams(page: import('@playwright/test').Page): Promise<void> {
  for (let i = 0; i < 25; i++) {
    await page.goto(TEAMS);
    const forms = page.locator('form[action$="/delete"]');
    if ((await forms.count()) === 0) return;
    await Promise.all([
      page.waitForResponse(
        (r) => /\/teams\/[^/]+\/delete$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST',
        { timeout: 15_000 },
      ),
      forms.first().locator('button[type="submit"]').click(),
    ]);
  }
}

test('same_group: guardrail, co-team visible, other-team hidden', async ({
  page,
  browser,
  request,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(!creds, 'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the same-group scenario');

  // Three members, auto-joined to Default. Keep A's context alive (A is the
  // viewer); B and C only need to exist.
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const ctxC = await browser.newContext();
  const pageA = await ctxA.newPage();
  const a = await registerUser(pageA, 'playwright-sg-a');
  const b = (await registerUser(await ctxB.newPage(), 'playwright-sg-b')).email;
  const c = (await registerUser(await ctxC.newPage(), 'playwright-sg-c')).email;
  await ctxB.close();
  await ctxC.close();
  const idB = await lookupIdentityId(request, b);
  const idC = await lookupIdentityId(request, c);

  await signInAdminAal2(page, creds!);
  page.on('dialog', (d) => d.accept());

  try {
    // Start clean so the guardrail is deterministic.
    await deleteAllTeams(page);

    // 1. Guardrail: same_group with no team is refused.
    const blocked = await setVisibility(page, 'same_group');
    expect(blocked.status()).toBe(400);
    expect(await blocked.text()).toContain('create a team before restricting to same-group');

    // 2. A + B in T1, C alone in T2.
    const t1 = await createTeam(page, `T1 ${Date.now()}`);
    const t2 = await createTeam(page, `T2 ${Date.now()}`);
    await addTeamMember(page, t1, await lookupIdentityId(request, a.email));
    await addTeamMember(page, t1, idB);
    await addTeamMember(page, t2, idC);

    const ok = await setVisibility(page, 'same_group');
    expect(ok.status()).toBe(303);

    // 3. A (plain member) sees self + co-team B, not C, on the roster.
    await pageA.goto(MEMBERS);
    const roster = (await pageA.locator('body').innerText()).toLowerCase();
    expect(roster).toContain(a.email.toLowerCase());
    expect(roster).toContain(b.toLowerCase());
    expect(roster).not.toContain(c.toLowerCase());

    // 4. Profile gate: co-team B is viewable, other-team C is a 404.
    const bResp = await pageA.goto(`/users/${idB}`);
    expect(bResp?.status()).toBe(200);
    expect((await pageA.locator('body').innerText()).toLowerCase()).toContain(b.toLowerCase());

    const cResp = await pageA.goto(`/users/${idC}`);
    expect(cResp?.status()).toBe(404);
  } finally {
    await setVisibility(page, 'admins_only');
    await deleteAllTeams(page);
    await ctxA.close();
  }
});
