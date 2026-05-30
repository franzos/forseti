// Scenario F: org invite email + accept + member-list landing.
//
// Covers the full multi-redirect path: admin POST → invite mail in
// Mailcrab → invitee clicks the link → portal recognises anonymous +
// hands off to Kratos registration with a `return_to=/invite/finalize`
// → finalize bounces to /invite/accept → invitee clicks the CSRF-
// protected accept form → membership row is written. The Rust suite
// has nothing here; this scenario is what proves the cross-step state
// machine survives a real browser.
//
// Skips when admin env vars aren't set (needs admin to send the invite).
import { test, expect } from '@playwright/test';
import { adminCredsFromEnv, signInAdminAal2 } from '../../helpers/admin';
import { uniqueEmail, registerUserWithEmail } from '../../helpers/register';
import { waitForMail } from '../../helpers/mailcrab';

const KRATOS_ADMIN = 'http://host.containers.internal:4434';

/**
 * Mark an identity's email as verified via Kratos admin API. The invite
 * accept handler refuses to write the membership row for an unverified
 * identity (`src/orgs/invite.rs::invite_accept_post`), and Kratos
 * registration doesn't auto-verify — so for the test to exercise the
 * "happy path" all the way through, we flip the verified flag here.
 *
 * IMPORTANT: PUT /admin/identities/{id} with a `verifiable_addresses`
 * array whose entries carry `verified: true` is silently ignored by
 * Kratos — the `verified` field is treated as server-controlled and
 * only the `code` self-service flow can set it. JSON Patch on
 * `/verifiable_addresses/0/verified` IS honoured, so we use that.
 */
async function markEmailVerified(
  request: import('@playwright/test').APIRequestContext,
  email: string,
): Promise<void> {
  const lookup = await request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`,
  );
  expect(lookup.ok()).toBeTruthy();
  const ids = (await lookup.json()) as Array<{
    id: string;
    verifiable_addresses?: Array<{ id: string; value: string; verified: boolean }>;
  }>;
  const identity = ids[0];
  expect(identity, `no identity for ${email}`).toBeTruthy();
  const idx = (identity.verifiable_addresses ?? []).findIndex(
    (a) => a.value.toLowerCase() === email.toLowerCase(),
  );
  expect(idx, `no verifiable_address for ${email}`).toBeGreaterThanOrEqual(0);

  const patch = await request.patch(`${KRATOS_ADMIN}/admin/identities/${identity.id}`, {
    headers: { 'content-type': 'application/json' },
    data: [
      { op: 'replace', path: `/verifiable_addresses/${idx}/verified`, value: true },
      { op: 'replace', path: `/verifiable_addresses/${idx}/status`, value: 'completed' },
    ],
  });
  expect(
    patch.ok(),
    `PATCH identity returned ${patch.status()}: ${await patch.text()}`,
  ).toBeTruthy();
}

test('org invite: admin mints → invitee redeems → member row lands', async ({
  browser,
  page,
  request,
}) => {
  const adminCreds = adminCredsFromEnv();
  test.skip(
    !adminCreds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the invite redemption scenario',
  );

  // 1. Admin signs in (AAL2) and lands on the org members page.
  await signInAdminAal2(page, adminCreds!);

  const inviteeEmail = uniqueEmail('playwright-invitee');

  // 2. Admin sends the invite. The form posts back to the members page
  //    on success (with no `error` query string). Use the page to
  //    auto-attach CSRF cookies — going via `request.post` would skip
  //    the cookie jar.
  await page.goto('/settings/organization/members');
  await page.locator('input[name="email"]').fill(inviteeEmail);
  // Role defaults to `member` if not set; the form's <select> defaults
  // to member, no action needed.
  await Promise.all([
    page.waitForURL(/\/settings\/organization\/members(?!.*error=)/, { timeout: 15_000 }),
    page.locator('form[action="/settings/organization/members/invite"] button[type="submit"]').click(),
  ]);

  // 3. Mailcrab delivers the invite. Subject format is
  //    `<inviter_email> invited you to <org_name> on <brand_name>` —
  //    see `src/ory/kratos.rs::send_invite_email`.
  const mail = await waitForMail(request, inviteeEmail, 'invited you to', 15_000);
  expect(mail.body).toContain('invited you to join');

  // 4. Pull the accept URL out of the body — it's emitted as
  //    `http://localhost:3000/invite/accept?token=...`.
  const acceptMatch = mail.body.match(/(https?:\/\/[^\s]+\/invite\/accept\?token=[A-Za-z0-9]+)/);
  expect(acceptMatch, `no accept URL in body: ${mail.body.slice(0, 400)}`).toBeTruthy();
  // Rewrite the host to whatever the test is hitting — the mail body
  // bakes the portal `self.url` (typically `http://localhost:3000`),
  // which from inside the playwright container needs to be
  // `host.containers.internal:3000`. `baseURL` already resolves there.
  const acceptUrl = acceptMatch![1].replace(
    /^https?:\/\/[^/]+/,
    process.env.BASE_URL || 'http://host.containers.internal:3000',
  );

  // 5. Fresh browser context for the invitee — don't carry the admin's
  //    cookies. (Re-using `page` would inherit the admin session and
  //    drop us into the "different account signed in" branch.)
  const inviteeContext = await browser.newContext();
  const inviteePage = await inviteeContext.newPage();
  try {
    await inviteePage.goto(acceptUrl);

    // Anonymous branch: CTA reads "Register as <email> and accept"
    // (`src/orgs/invite.rs::invite_accept_get`, the `cta_label` field).
    const cta = inviteePage.getByText(`Register as ${inviteeEmail} and accept`);
    await expect(cta).toBeVisible();

    // 6. Click through to Kratos registration. The `return_to` baked into
    //    the URL points at /invite/finalize?token=..., which after
    //    registration completes redirects to /invite/accept?token=...
    //    where the user is now signed in.
    await cta.click();
    await inviteePage.waitForURL((u) => u.pathname.startsWith('/registration'), {
      timeout: 15_000,
    });

    // 7. Complete the two-step registration with the invited email.
    //    `registerUserWithEmail` handles the profile + password steps;
    //    it waits for a non-/registration URL on submit.
    await registerUserWithEmail(inviteePage, inviteeEmail);

    // 8. Registration auto-signs-in. The `return_to` runs after the
    //    registration after-hook chain, dropping us on /invite/finalize
    //    which bounces to /invite/accept. The "signed in + email
    //    matches" branch refuses unverified identities, so we mark the
    //    email verified via the admin API before clicking accept.
    await markEmailVerified(request, inviteeEmail);

    // 9. Navigate to the accept page (in case the finalize redirect
    //    raced us, or landed somewhere else). Then click the CSRF-
    //    protected accept form.
    await inviteePage.goto(acceptUrl);
    const joinBtn = inviteePage.locator('form[action="/invite/accept"] button[type="submit"]');
    await expect(joinBtn).toBeVisible({ timeout: 15_000 });
    await Promise.all([
      inviteePage.waitForURL((u) => u.pathname === '/' || u.pathname.startsWith('/settings'), {
        timeout: 15_000,
      }),
      joinBtn.click(),
    ]);

    // 10. Confirm the invitee can see the members page and is listed
    //     there with role `member`. The page is owner-gated on the
    //     write surfaces, but the read renders for any member.
    await inviteePage.goto('/settings/organization/members');
    const bodyText = await inviteePage.locator('body').innerText();
    expect(bodyText.toLowerCase()).toContain(inviteeEmail.toLowerCase());
  } finally {
    await inviteeContext.close();
  }
});
