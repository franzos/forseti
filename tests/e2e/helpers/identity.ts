// Identity-backend seam for the specs. The Ory build answers through the
// Kratos admin (:4434) and public (:4433) APIs; the native build
// (`FORSETI_IDENTITY_BACKEND=native`, set by `make e2e-native`) has no Kratos,
// so lookups read Forseti's sqlite file (`FORSETI_DB_PATH`, mounted into the
// container) and session probes go through Forseti itself.
//
// Writes that need the server's keys (password hashes, TOTP secrets) never
// happen here: specs drive the UI for those. The one native write is
// `markEmailVerified`, the counterpart of the Kratos JSON Patch.
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { APIRequestContext, BrowserContext } from '@playwright/test';
import { expect } from '@playwright/test';

export const isNative = process.env.FORSETI_IDENTITY_BACKEND === 'native';

/** Name of the session cookie the identity backend sets on the portal origin. */
export const SESSION_COOKIE = isNative ? 'forseti_session' : 'ory_kratos_session';

/** Storage state of the admin session `global-setup.ts` signs in on native. */
export const ADMIN_STATE = join(tmpdir(), 'forseti-e2e-admin-state.json');

interface SessionCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
}

/**
 * The session cookie of the admin signed in by `global-setup.ts`. Native only:
 * every spec reuses that one AAL2 session, because the TOTP replay guard
 * accepts one code per 30 s step.
 */
export function adminSessionCookies(): SessionCookie[] {
  const state = JSON.parse(readFileSync(ADMIN_STATE, 'utf8')) as { cookies: SessionCookie[] };
  const cookies = state.cookies.filter((c) => c.name === SESSION_COOKIE);
  if (cookies.length === 0) throw new Error(`no ${SESSION_COOKIE} cookie in ${ADMIN_STATE}`);
  return cookies.map(({ name, value, domain, path }) => ({ name, value, domain, path }));
}

/** Whether `context` carries the shared native admin session. */
export async function holdsSharedAdminSession(context: BrowserContext): Promise<boolean> {
  if (!isNative) return false;
  const admin = new Set(adminSessionCookies().map((c) => c.value));
  return (await context.cookies()).some((c) => c.name === SESSION_COOKIE && admin.has(c.value));
}

const KRATOS_ADMIN = process.env.KRATOS_ADMIN || 'http://host.containers.internal:4434';
const KRATOS_PUBLIC = process.env.KRATOS_PUBLIC || 'http://host.containers.internal:4433';
const BASE = process.env.BASE_URL || 'http://host.containers.internal:3000';
const DB_PATH = process.env.FORSETI_DB_PATH || '/forseti/forseti.db';

interface SqliteStatement {
  get(...params: unknown[]): Record<string, unknown> | undefined;
  run(...params: unknown[]): { changes: number | bigint };
}

interface SqliteDatabase {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
  close(): void;
}

// `node:sqlite` loads lazily so Ory runs never touch it.
async function withDb<T>(readOnly: boolean, fn: (db: SqliteDatabase) => T): Promise<T> {
  const { DatabaseSync } = (await import('node:sqlite')) as {
    DatabaseSync: new (path: string, opts: { readOnly: boolean }) => SqliteDatabase;
  };
  const db = new DatabaseSync(DB_PATH, { readOnly });
  try {
    // The server writes the same file; wait out its locks instead of failing.
    db.exec('PRAGMA busy_timeout = 5000');
    return fn(db);
  } finally {
    db.close();
  }
}

interface KratosIdentity {
  id: string;
  verifiable_addresses?: Array<{ id: string; value: string; verified: boolean }>;
}

async function kratosIdentity(
  request: APIRequestContext,
  email: string,
): Promise<KratosIdentity | undefined> {
  const res = await request.get(
    `${KRATOS_ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`,
  );
  expect(res.ok(), `Kratos identity lookup for ${email} returned ${res.status()}`).toBeTruthy();
  return ((await res.json()) as KratosIdentity[])[0];
}

/** Identity id for a login email, or `undefined` when no identity has it. */
export async function identityIdByEmail(
  request: APIRequestContext,
  email: string,
): Promise<string | undefined> {
  if (!isNative) return (await kratosIdentity(request, email))?.id;
  const row = await withDb(true, (db) =>
    db.prepare('SELECT id FROM identities WHERE email_norm = ?').get(email.toLowerCase()),
  );
  return row?.id as string | undefined;
}

/** As {@link identityIdByEmail}, failing the test when the identity is missing. */
export async function requireIdentityId(request: APIRequestContext, email: string): Promise<string> {
  const id = await identityIdByEmail(request, email);
  expect(id, `no identity for ${email}`).toBeTruthy();
  return id!;
}

/**
 * Mark an identity's email verified. Membership writes and sign-in refuse
 * unverified addresses, and registration doesn't verify. On Kratos, JSON Patch
 * on `/verifiable_addresses/{i}/verified` is the only shape honoured (a
 * whole-object PUT silently drops `verified`).
 */
export async function markEmailVerified(request: APIRequestContext, email: string): Promise<void> {
  if (isNative) {
    const changes = await withDb(false, (db) =>
      db
        .prepare(
          'UPDATE identities SET email_verified_at = COALESCE(email_verified_at, ?) WHERE email_norm = ?',
        )
        .run(new Date().toISOString(), email.toLowerCase()).changes,
    );
    expect(Number(changes), `no identity for ${email}`).toBe(1);
    return;
  }
  const identity = await kratosIdentity(request, email);
  expect(identity, `no identity for ${email}`).toBeTruthy();
  const idx = (identity!.verifiable_addresses ?? []).findIndex(
    (a) => a.value.toLowerCase() === email.toLowerCase(),
  );
  expect(idx, `no verifiable_address for ${email}`).toBeGreaterThanOrEqual(0);
  const patch = await request.patch(`${KRATOS_ADMIN}/admin/identities/${identity!.id}`, {
    headers: { 'content-type': 'application/json' },
    data: [
      { op: 'replace', path: `/verifiable_addresses/${idx}/verified`, value: true },
      { op: 'replace', path: `/verifiable_addresses/${idx}/status`, value: 'completed' },
    ],
  });
  expect(patch.ok(), `PATCH identity returned ${patch.status()}: ${await patch.text()}`).toBeTruthy();
}

/**
 * Whether the session behind `cookieHeader` is still live. Kratos: whoami
 * answers anything but 401. Native: `GET /settings` does not bounce to /login.
 */
export async function sessionIsActive(
  request: APIRequestContext,
  cookieHeader: string,
): Promise<boolean> {
  if (!isNative) {
    const whoami = await request.get(`${KRATOS_PUBLIC}/sessions/whoami`, {
      headers: { cookie: cookieHeader },
      failOnStatusCode: false,
    });
    return whoami.status() !== 401;
  }
  const res = await request.get(`${BASE}/settings`, {
    headers: { cookie: cookieHeader },
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  const location = res.headers()['location'] ?? '';
  return !(res.status() >= 300 && res.status() < 400 && location.startsWith('/login'));
}
