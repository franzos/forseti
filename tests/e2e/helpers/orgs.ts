// Org-directory test helpers: thin wrappers over the real settings forms
// (members + teams) plus the Kratos-admin email-verify shim the membership
// writes require. Everything drives the rendered DOM via the page so the
// hidden `_csrf` field and its cookie travel together — a raw request.post
// would skip the cookie jar and 403.
import type { APIRequestContext, Browser, BrowserContext, Page, Response } from '@playwright/test';
import { expect } from '@playwright/test';
import { registerUserWithEmail } from './register';
import { waitForMail } from './mailcrab';

const BASE = process.env.BASE_URL || 'http://host.containers.internal:3000';
const KRATOS_ADMIN = process.env.KRATOS_ADMIN || 'http://host.containers.internal:4434';

/** Settings base path for an org: Default (singular) when `slug` is null. */
export function orgBase(slug?: string | null): string {
  return slug ? `/settings/organizations/${slug}` : '/settings/organization';
}

/**
 * Mark an identity's email verified via Kratos admin API. Membership writes
 * (invite accept, in particular) refuse unverified identities and Kratos
 * registration doesn't auto-verify, so flip the flag here. JSON Patch on
 * `/verifiable_addresses/{i}/verified` is the only shape Kratos honours — a
 * whole-object PUT silently drops `verified`. Mirrors the pattern proven in
 * `f-org-invite-redemption.spec.ts`.
 */
export async function markEmailVerified(request: APIRequestContext, email: string): Promise<void> {
  const identity = await getIdentity(request, email);
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
  expect(patch.ok(), `PATCH identity returned ${patch.status()}: ${await patch.text()}`).toBeTruthy();
}

/** Resolve a Kratos identity UUID from its login email. */
export async function lookupIdentityId(request: APIRequestContext, email: string): Promise<string> {
  return (await getIdentity(request, email)).id;
}

interface KratosIdentity {
  id: string;
  verifiable_addresses?: Array<{ id: string; value: string; verified: boolean }>;
}

async function getIdentity(request: APIRequestContext, email: string): Promise<KratosIdentity> {
  const res = await request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`,
  );
  expect(res.ok(), `Kratos identity lookup for ${email} returned ${res.status()}`).toBeTruthy();
  const ids = (await res.json()) as KratosIdentity[];
  const identity = ids[0];
  expect(identity, `no identity for ${email}`).toBeTruthy();
  return identity;
}

/**
 * Create a non-default (commercial) org via the multi-org settings form.
 * Caller must already be signed in as a user allowed to create orgs (admin /
 * licensed). Returns the slug the redirect landed on. `mode`, when set,
 * selects the matching access-mode radio before submit.
 */
export async function createOrg(
  page: Page,
  name: string,
  slug?: string,
  mode?: 'internal' | 'external',
): Promise<string> {
  await page.goto('/settings/organizations');
  const form = page.locator('form[action="/settings/organizations/create"]');
  await form.locator('input[name="name"]').fill(name);
  if (slug) {
    await form.locator('input[name="slug"]').fill(slug);
  }
  if (mode) {
    await form.locator(`input[name="access_mode"][value="${mode}"]`).check();
  }
  await Promise.all([
    page.waitForURL((u) => /\/settings\/organizations\/[^/]+$/.test(u.pathname), { timeout: 15_000 }),
    form.locator('button[type="submit"]').click(),
  ]);
  const m = new URL(page.url()).pathname.match(/\/settings\/organizations\/([^/]+)$/);
  expect(m, `org create did not land on an org page: ${page.url()}`).toBeTruthy();
  return m![1];
}

/**
 * Switch an org's access mode via the confirmed overview form and return the
 * POST `Response`. `slug` null targets the Default org (though the Default
 * org's switch form never renders since it's always internal).
 */
export async function setAccessMode(
  page: Page,
  mode: 'internal' | 'external',
  slug?: string | null,
): Promise<Response> {
  const base = orgBase(slug);
  await page.goto(base);
  const form = page.locator(`form[action="${base}/access-mode"]`);
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes('/access-mode') && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    form.locator('button[type="submit"]').click(),
  ]);
  return resp;
}

/**
 * Set the directory-visibility policy. Returns the raw POST `Response` so the
 * caller can assert the 400 guardrail (same_group with no team) as well as the
 * 303 happy path. `slug` null targets the Default org.
 */
export async function setVisibility(
  page: Page,
  value: 'all' | 'same_group' | 'admins_only',
  slug?: string | null,
): Promise<Response> {
  const base = orgBase(slug);
  await page.goto(`${base}/members`);
  const form = page.locator(`form[action="${base}/members/visibility"]`);
  await form.locator('select[name="visibility"]').selectOption(value);
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes('/members/visibility') && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    form.locator('button[type="submit"]').click(),
  ]);
  return resp;
}

/**
 * Create a team and return its id (parsed from the rename-form action on the
 * row that lands back on the teams page). `slug` null targets the Default org.
 * Caller must be an owner of a licensed org (teams gate on `Feature::Orgs`).
 */
export async function createTeam(page: Page, name: string, slug?: string | null): Promise<string> {
  const base = orgBase(slug);
  await page.goto(`${base}/teams`);
  const createForm = page.locator(`form[action="${base}/teams"]`);
  await createForm.locator('input[name="name"]').fill(name);
  await Promise.all([
    page.waitForURL((u) => u.pathname === `${base}/teams`, { timeout: 15_000 }),
    createForm.locator('button[type="submit"]').click(),
  ]);
  const renameForm = page
    .locator(`form[action$="/rename"]:has(input[value="${name}"])`)
    .first();
  await renameForm.waitFor({ state: 'attached', timeout: 15_000 });
  const action = await renameForm.getAttribute('action');
  const m = action?.match(/\/teams\/([^/]+)\/rename$/);
  expect(m, `could not parse team id from ${action}`).toBeTruthy();
  return m![1];
}

/** Add an org member to a team via the manage-members panel (`?team=`). */
export async function addTeamMember(
  page: Page,
  teamId: string,
  identityId: string,
  slug?: string | null,
): Promise<void> {
  const base = orgBase(slug);
  await page.goto(`${base}/teams?team=${teamId}`);
  const addForm = page.locator(`form[action="${base}/teams/${teamId}/members"]`);
  await addForm.locator('select[name="identity_id"]').selectOption(identityId);
  // Wait on the POST itself, not the URL: the redirect lands back on the same
  // path, so `waitForURL` would resolve before the write commits.
  await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes(`/teams/${teamId}/members`) && r.request().method() === 'POST',
      { timeout: 15_000 },
    ),
    addForm.locator('button[type="submit"]').click(),
  ]);
}

/**
 * Owner sends an invite from the org members page and returns the accept URL
 * pulled from Mailcrab (host rewritten to the test base). Caller must be
 * signed in as an owner of the target org.
 */
export async function inviteMember(
  page: Page,
  request: APIRequestContext,
  opts: { email: string; role?: 'member' | 'owner'; slug?: string | null },
): Promise<string> {
  const base = orgBase(opts.slug);
  await page.goto(`${base}/members`);
  const form = page.locator(`form[action="${base}/members/invite"]`);
  await form.locator('input[name="email"]').fill(opts.email);
  if (opts.role) await form.locator('select[name="role"]').selectOption(opts.role);
  await Promise.all([
    page.waitForURL((u) => u.pathname === `${base}/members` && !u.search.includes('error='), {
      timeout: 15_000,
    }),
    form.locator('button[type="submit"]').click(),
  ]);
  const mail = await waitForMail(request, opts.email, 'invited you to', 20_000);
  const m = mail.body.match(/(https?:\/\/[^\s]+\/invite\/accept\?token=[A-Za-z0-9]+)/);
  expect(m, `no accept URL in invite body: ${mail.body.slice(0, 400)}`).toBeTruthy();
  return m![1].replace(/^https?:\/\/[^/]+/, BASE);
}

export interface AcceptedInvitee {
  context: BrowserContext;
  page: Page;
  identityId: string;
}

/**
 * Redeem an invite in a fresh browser context: click the anonymous CTA →
 * register → verify the email (Kratos admin) → confirm the accept form. The
 * returned context stays signed in as the invitee so the caller can drive
 * profile / members views from their perspective; caller must close it.
 */
export async function acceptInvite(
  browser: Browser,
  request: APIRequestContext,
  acceptUrl: string,
  email: string,
): Promise<AcceptedInvitee> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(acceptUrl);
  await page.getByText(`Register as ${email} and accept`).click();
  await page.waitForURL((u) => u.pathname.startsWith('/registration'), { timeout: 15_000 });
  await registerUserWithEmail(page, email);
  await markEmailVerified(request, email);
  await page.goto(acceptUrl);
  const join = page.locator('form[action="/invite/accept"] button[type="submit"]');
  await expect(join).toBeVisible({ timeout: 15_000 });
  await Promise.all([
    page.waitForURL((u) => u.pathname === '/' || u.pathname.startsWith('/settings'), {
      timeout: 15_000,
    }),
    join.click(),
  ]);
  const identityId = await lookupIdentityId(request, email);
  return { context, page, identityId };
}

/** Compose invite + accept; returns the signed-in invitee context + id. */
export async function inviteAndAccept(
  adminPage: Page,
  browser: Browser,
  request: APIRequestContext,
  opts: { email: string; role?: 'member' | 'owner'; slug?: string | null },
): Promise<AcceptedInvitee> {
  const acceptUrl = await inviteMember(adminPage, request, opts);
  return acceptInvite(browser, request, acceptUrl, opts.email);
}
