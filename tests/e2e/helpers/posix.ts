// Admin POSIX/host test helpers. Thin wrappers over the real /admin/posix and
// /admin/hosts forms. Caller must already be signed in as the AAL2 admin
// (these surfaces are RequireAdmin: session + AAL2 + allow-listed email).
import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

/**
 * Provision a POSIX account for an identity. Drives the two-step form by
 * pre-seeding `?identity_id=` so step 2 (username + shell) renders directly,
 * then submits. Lands on `/admin/posix/{identity_id}`.
 */
export async function provisionAccount(
  page: Page,
  identityId: string,
  username: string,
  shell?: string,
): Promise<void> {
  await page.goto(`/admin/posix/new?identity_id=${encodeURIComponent(identityId)}`);
  // With `identity_id` seeded, the template renders only the step-2 POST form
  // (the step-1 chooser branch is hidden), so this matches uniquely.
  const form = page.locator('form[method="POST"][action="/admin/posix/new"]');
  await form.locator('input[name="username"]').fill(username);
  if (shell) await form.locator('input[name="shell"]').fill(shell);
  await Promise.all([
    page.waitForURL((u) => u.pathname.startsWith('/admin/posix/') && !u.pathname.endsWith('/new'), {
      timeout: 15_000,
    }),
    form.locator('button[type="submit"]:has-text("Provision account")').click(),
  ]);
}

export interface EnrolledHost {
  hostId: string;
  secret: string;
}

/**
 * Enroll a Linux host and return its one-shot `host_id:secret`, parsed from
 * the reveal banner the redirect lands on. Select the org by id (`orgId`) or
 * by its display name (`orgLabel`); `teamIds` checks the matching team
 * checkboxes (must belong to the chosen org).
 */
export async function enrollHost(
  page: Page,
  opts: { hostname: string; orgId?: string; orgLabel?: string; teamIds?: string[]; forceMfa?: boolean },
): Promise<EnrolledHost> {
  await page.goto('/admin/hosts/new');
  await page.locator('input[name="hostname"]').fill(opts.hostname);
  if (opts.orgId) {
    await page.locator('select[name="org_id"]').selectOption(opts.orgId);
  } else if (opts.orgLabel) {
    await page.locator('select[name="org_id"]').selectOption({ label: opts.orgLabel });
  }
  for (const teamId of opts.teamIds ?? []) {
    await page.locator(`input[name="team_ids"][value="${teamId}"]`).check();
  }
  if (opts.forceMfa) await page.locator('input[name="force_mfa"]').check();
  await Promise.all([
    page.waitForURL((u) => u.pathname === '/admin/hosts' && u.search.includes('reveal='), {
      timeout: 15_000,
    }),
    page.locator('button[type="submit"]:has-text("Enroll host")').click(),
  ]);
  const cred = (await page.locator('pre.break-all').first().innerText()).trim();
  const idx = cred.indexOf(':');
  expect(idx, `host credential not in host_id:secret form: ${cred}`).toBeGreaterThan(0);
  return { hostId: cred.slice(0, idx), secret: cred.slice(idx + 1) };
}

/**
 * Re-scope an existing host to a set of teams via the edit form. The host's
 * org is fixed at enrollment (read-only here); `teamIds` must be teams of
 * that org. Replaces the host's current team scope.
 */
export async function scopeHostToTeam(
  page: Page,
  hostId: string,
  teamIds: string[],
): Promise<void> {
  await page.goto(`/admin/hosts/${hostId}/edit`);
  // Clear any pre-checked boxes, then check the requested ones, so the call
  // is a set-replace rather than an additive toggle.
  const boxes = page.locator('input[name="team_ids"]');
  for (let i = 0; i < (await boxes.count()); i++) {
    await boxes.nth(i).uncheck();
  }
  for (const teamId of teamIds) {
    await page.locator(`input[name="team_ids"][value="${teamId}"]`).check();
  }
  await Promise.all([
    page.waitForURL((u) => u.pathname === '/admin/hosts', { timeout: 15_000 }),
    page.locator('button[type="submit"]:has-text("Save")').click(),
  ]);
}
