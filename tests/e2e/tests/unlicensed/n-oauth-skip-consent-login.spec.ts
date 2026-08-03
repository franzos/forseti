// Scenario N: sign in from inside an authorize chain for a client that skips
// consent. The whole run — Kratos login POST → portal /oauth/login → Hydra →
// portal /oauth/consent (auto-grant) → Hydra → the client's redirect_uri — is
// one navigation started by a form submission, and `form-action` is enforced
// across every hop of it. Miss the client's origin in the header and the
// browser silently drops the last redirect: the server logs a clean 303 and
// the user sits on the login (or second-factor) page.
//
// Scenario B can't catch this: it unchecks `skip_consent` and clicks Allow, so
// the last hop starts from the consent page, which already allowlists the
// client's redirect URIs.
//
// The second case covers the step-up render, where `return_to` exists only
// inside the Kratos flow (the URL is a bare `/login?flow=…`) — that's the shape
// a 2FA user actually hits.
import { test, expect, type Page, type APIRequestContext } from '@playwright/test';
import { registerUser, logout } from '../../helpers/register';
import { adminCredsFromEnv } from '../../helpers/admin';
import { computeTotp } from '../../helpers/totp';
import { generatePkcePair } from '../../helpers/oauth';

const HYDRA_AUTHORIZE = 'http://host.containers.internal:4444/oauth2/auth';
const HYDRA_ADMIN = 'http://localhost:4445';
// Unreachable on purpose — the assertion is the navigation attempt, not a page.
const REDIRECT_URI = 'http://localhost:9876/cb';

/**
 * Public client with `skip_consent`, created straight through Hydra's admin
 * API so the scenarios don't need a portal admin session.
 */
async function createSkipConsentClient(request: APIRequestContext, label: string): Promise<string> {
  const created = await request.post(`${HYDRA_ADMIN}/admin/clients`, {
    data: {
      client_name: `e2e-skip-consent-${label}-${Date.now()}`,
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid email profile offline_access',
      token_endpoint_auth_method: 'none',
      skip_consent: true,
    },
  });
  expect(created.ok()).toBeTruthy();
  return (await created.json()).client_id as string;
}

/** Start the authorize request for `clientId` in the browser. */
async function startAuthorize(page: Page, clientId: string): Promise<void> {
  const pkce = generatePkcePair();
  const authUrl = new URL(HYDRA_AUTHORIZE);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', `e2e-state-${Date.now()}`);
  // Hydra enforces PKCE for public clients; without it the last hop still
  // fires but carries `error=invalid_request` instead of a code.
  authUrl.searchParams.set('code_challenge', pkce.challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  await page.goto(authUrl.toString());
}

/** Collect CSP violations so a blocked hop reports as more than a timeout. */
function watchCsp(page: Page): string[] {
  const violations: string[] = [];
  page.on('console', (msg) => {
    if (/Content Security Policy|form-action/i.test(msg.text())) violations.push(msg.text());
  });
  return violations;
}

async function expectCallback(
  page: Page,
  callback: Promise<{ url(): string } | null>,
  cspViolations: string[],
): Promise<void> {
  const req = await callback.catch(() => null);
  expect(
    req,
    `never reached ${REDIRECT_URI}; stuck at ${page.url()}. CSP: ${cspViolations.join(' | ') || 'none logged'}`,
  ).not.toBeNull();
  expect(new URL(req!.url()).searchParams.get('code')).toBeTruthy();
  expect(cspViolations, cspViolations.join(' | ')).toHaveLength(0);
}

test('login inside an authorize chain reaches a skip-consent client callback', async ({
  page,
  request,
}) => {
  const clientId = await createSkipConsentClient(request, 'pwd');

  // A fresh user, signed out again: the authorize chain has to run the login
  // form itself, which is the navigation under test.
  const user = await registerUser(page, 'playwright-skip-consent');
  await logout(page);

  const cspViolations = watchCsp(page);
  await startAuthorize(page, clientId);

  await page.waitForURL((u) => u.pathname.startsWith('/login'));
  await page.locator('input[name="identifier"]').fill(user.email);
  await page.locator('input[name="password"]').fill(user.password);

  const callback = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI), {
    timeout: 20_000,
  });
  await page.locator('button[name="method"][value="password"]').click();
  await expectCallback(page, callback, cspViolations);

  await request.delete(`${HYDRA_ADMIN}/admin/clients/${clientId}`);
});

test('second-factor submit inside an authorize chain reaches the callback', async ({
  page,
  request,
}) => {
  const creds = adminCredsFromEnv();
  test.skip(
    !creds,
    'Set FORSETI_ADMIN_TEST_{EMAIL,PASSWORD,TOTP_SECRET} to run the second-factor scenario',
  );

  const clientId = await createSkipConsentClient(request, 'aal2');
  const cspViolations = watchCsp(page);

  await startAuthorize(page, clientId);
  await page.waitForURL((u) => u.pathname.startsWith('/login'));
  // Password on the flow the authorize chain handed us — never `goto('/login')`,
  // which starts a fresh flow and drops the OAuth `return_to`. With
  // `required_aal: highest_available` the TOTP step then renders as a second
  // login flow whose URL is a bare `/login?flow=…`, so the `return_to` survives
  // only inside the flow body.
  await page.locator('input[name="identifier"]').fill(creds!.email);
  await page.locator('input[name="password"]').fill(creds!.password);
  await page.locator('button[name="method"][value="password"]').click();

  const totpInput = page.locator('input[name="totp_code"]');
  await totpInput.waitFor({ state: 'visible' });
  await totpInput.fill(computeTotp(creds!.totpSecret));

  const callback = page.waitForRequest((req) => req.url().startsWith(REDIRECT_URI), {
    timeout: 20_000,
  });
  await page.locator('button[name="method"][value="totp"]').click();
  await expectCallback(page, callback, cspViolations);

  await request.delete(`${HYDRA_ADMIN}/admin/clients/${clientId}`);
});
