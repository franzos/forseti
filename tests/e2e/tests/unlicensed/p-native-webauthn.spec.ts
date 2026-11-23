// Scenario P (native only): passkeys and security keys through the real
// `static/webauthn.js` and Chromium's virtual authenticators.
//
// The Rust suite drives every ceremony with a software authenticator whose
// JSON mirrors the script's. What only a browser shows: the script reads the
// options the page renders, `navigator.credentials.create/get` accept them,
// and the credential JSON it posts is what the server verifies.
//
// Each test attaches its authenticators to its own page, so credentials never
// leak between tests; signing out and in again keeps the page and its keys.
import { test, expect, type Page } from '@playwright/test';
import { backdateSignIn, isNative, liveSession, markEmailVerified } from '../../helpers/identity';
import { extractSixDigitCode, waitForMail } from '../../helpers/mailcrab';
import { logout, registerUser, uniqueEmail } from '../../helpers/register';
import {
  addPasskeyAuthenticator,
  addSecurityKeyAuthenticator,
  credentialCount,
  removeAuthenticator,
} from '../../helpers/webauthn';

test.skip(!isNative, 'Forseti serves its own WebAuthn ceremonies only on the native build');

const NEW_PASSWORD = 'Sup3rSecret-E2E-Passkey-Password!';

async function scriptReady(page: Page, fn: string): Promise<void> {
  await page.waitForFunction((name) => typeof (window as any)[name] === 'function', fn);
}

/** Sign up with a passkey on the attached platform authenticator and enter the mailed code. */
async function signUpWithPasskey(page: Page, prefix: string): Promise<string> {
  const email = uniqueEmail(prefix);
  await page.goto('/registration');
  await page.locator('input[name="traits.email"]').fill(email);
  await page.locator('input[name="traits.name.first"]').fill('Pass');
  await page.locator('input[name="traits.name.last"]').fill('Key');
  await page.locator('button[name="method"][value="profile"]').click();

  const trigger = page.locator('button[name="passkey_register_trigger"]');
  await trigger.waitFor({ state: 'visible', timeout: 15_000 });
  await scriptReady(page, 'oryPasskeyRegistration');
  await expect(trigger).toBeEnabled();
  await trigger.click();

  await page.waitForURL(/\/verification\?flow=/, { timeout: 15_000 });
  const mail = await waitForMail(page.request, email, 'verify your account');
  await page.locator('input[name="code"]').fill(extractSixDigitCode(mail.body));
  await page.locator('button[name="method"][value="code"]').click();
  await expect(page.locator('input[name="code"]')).toHaveCount(0, { timeout: 15_000 });
  return email;
}

/** Sign in from a fresh login page through the passkey button. */
async function signInWithPasskey(page: Page): Promise<void> {
  await page.goto('/login');
  const trigger = page.locator('button[name="passkey_login_trigger"]');
  await scriptReady(page, 'oryPasskeyLogin');
  await expect(trigger).toBeEnabled();
  await trigger.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });
}

/** Submit the password step; the caller asserts where it lands. */
async function submitPassword(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.locator('input[name="identifier"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button[name="method"][value="password"]').click();
}

/** Add a security key in /settings/2fa on the attached USB authenticator. */
async function addSecurityKey(page: Page, name: string): Promise<void> {
  await page.goto('/settings/2fa');
  await scriptReady(page, 'oryWebAuthnRegistration');
  await page.locator('input[name="webauthn_register_displayname"]').fill(name);
  await page.locator('button[name="webauthn_register_trigger"]').click();
  const removeKey = page.locator('button[name="webauthn_remove"]');
  await expect(removeKey).toHaveCount(1, { timeout: 15_000 });
  await expect(removeKey).toContainText(name);
}

test('a passkey and a security key are added in /settings/2fa', async ({ page }) => {
  const user = await registerUser(page, 'playwright-webauthn');
  await markEmailVerified(page.request, user.email);

  // Passkey first: the platform authenticator must exist when the page loads.
  const platform = await addPasskeyAuthenticator(page);
  await page.goto('/settings/2fa');
  await scriptReady(page, 'oryPasskeySettingsRegistration');
  const addPasskey = page.locator('button[name="passkey_register_trigger"]');
  await expect(addPasskey).toBeEnabled();
  await addPasskey.click();
  await expect(page.locator('button[name="passkey_remove"]')).toHaveCount(1, { timeout: 15_000 });
  await expect(page).toHaveURL(/\/settings\/2fa/);
  expect(await credentialCount(platform)).toBe(1);
  await removeAuthenticator(platform);

  // Then a USB key, alone, so the browser cannot hand the ceremony to the platform one.
  const usb = await addSecurityKeyAuthenticator(page);
  await addSecurityKey(page, 'Playwright key');
  expect(await credentialCount(usb)).toBe(1);

  // Both keys are listed with their remove buttons; the first security key opened lookup codes.
  await expect(page).toHaveURL(/\/settings\/2fa/);
  await expect(page.locator('button[name="passkey_remove"]')).toHaveCount(1);
  await expect(page.locator('button[name="passkey_remove"]')).toContainText('Passkey');
  await expect(page.locator('button[name="lookup_secret_regenerate"]')).toBeVisible();
});

test('signs up with a passkey, verifies, signs out and signs in with it', async ({ page }) => {
  const platform = await addPasskeyAuthenticator(page);
  const email = await signUpWithPasskey(page, 'playwright-passkey-signup');
  expect(await credentialCount(platform)).toBe(1);

  await logout(page);
  expect(await liveSession(email)).toBeUndefined();

  await signInWithPasskey(page);
  expect(await liveSession(email)).toEqual({ aal: 'aal1', methods: ['passkey'] });
});

test('a password account signs in and passes AAL2 with its security key', async ({ page }) => {
  const user = await registerUser(page, 'playwright-key-aal2');
  await markEmailVerified(page.request, user.email);
  await addSecurityKeyAuthenticator(page);
  await addSecurityKey(page, 'Playwright key');

  await logout(page);
  await submitPassword(page, user.email, user.password);
  const trigger = page.locator('button[name="webauthn_login_trigger"]');
  await expect(trigger).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('input[name="password"]')).toHaveCount(0);
  await scriptReady(page, 'oryWebAuthnLogin');
  await trigger.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });

  const session = await liveSession(user.email);
  expect(session?.aal).toBe('aal2');
  expect(session?.methods).toEqual(['password', 'webauthn']);
});

test('after the security key is removed, sign-in asks for no second factor', async ({ page }) => {
  const user = await registerUser(page, 'playwright-key-removed');
  await markEmailVerified(page.request, user.email);
  await addSecurityKeyAuthenticator(page);
  await addSecurityKey(page, 'Playwright key');

  await page.locator('button[name="webauthn_remove"]').click();
  await expect(page.locator('button[name="webauthn_remove"]')).toHaveCount(0, { timeout: 15_000 });
  await expect(page).toHaveURL(/\/settings\/2fa/);
  await expect(page.locator('button[name="lookup_secret_regenerate"]')).toHaveCount(0);

  await logout(page);
  await submitPassword(page, user.email, user.password);
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });
  expect(await liveSession(user.email)).toEqual({ aal: 'aal1', methods: ['password'] });
});

test('a passkey re-authentication opens the privileged window for a settings change', async ({
  page,
}) => {
  await addPasskeyAuthenticator(page);
  const email = await signUpWithPasskey(page, 'playwright-passkey-refresh');
  await backdateSignIn(email, 60);

  // Setting a password outside the privileged window asks for a re-authentication.
  await page.goto('/settings/password');
  await page.locator('input[name="password"]').fill(NEW_PASSWORD);
  // The refresh login passes through `/login?refresh=true` on its way to the flow page.
  const toRefresh = page.waitForRequest(/\/login\?refresh=true/, { timeout: 15_000 });
  await page.locator('button[name="method"][value="password"]').click();
  await toRefresh;
  const trigger = page.locator('button[name="passkey_login_trigger"]');
  await expect(trigger).toBeVisible({ timeout: 15_000 });

  // The account has no password yet, so the refresh page offers the passkey alone.
  await expect(page.locator('input[name="password"]')).toHaveCount(0);
  await scriptReady(page, 'oryPasskeyLogin');
  await expect(trigger).toBeEnabled();
  await trigger.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });
  expect((await liveSession(email))?.methods).toContain('passkey');

  await page.goto('/settings/password');
  await page.locator('input[name="password"]').fill(NEW_PASSWORD);
  const saved = page.waitForResponse(
    (r) => r.request().method() === 'POST' && r.url().includes('/self-service/settings'),
  );
  await page.locator('button[name="method"][value="password"]').click();
  expect((await saved).headers()['location'] ?? '').not.toContain('/login');
  await page.waitForLoadState();
  await expect(page).toHaveURL(/\/settings/);

  // The password went through: it signs the account in.
  await logout(page);
  await submitPassword(page, email, NEW_PASSWORD);
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 });
  expect(await liveSession(email)).toEqual({ aal: 'aal1', methods: ['password'] });
});
