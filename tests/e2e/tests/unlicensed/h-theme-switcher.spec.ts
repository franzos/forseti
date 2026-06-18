// Scenario H: dark / light / system theme switching.
//
// The mechanism (cookie -> server-rendered <html class>, the footer control,
// localStorage mirror, prefers-color-scheme resolution) is fully exercisable
// on the unauthenticated /login page (card.html root includes the footer
// control). We assert the server-rendered class / data-theme / cookie rather
// than computed colours, since the compiled stylesheet isn't a dependency of
// the switching mechanism.
import { test, expect } from '@playwright/test';
import { registerUser } from '../../helpers/register';

const TOGGLE = '[data-theme-toggle]';
const opt = (v: string) => `${TOGGLE} [data-theme-value="${v}"]`;

test.describe('theme switcher', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  test('default follows the OS colour scheme', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/login');
    await expect(page.locator('html')).not.toHaveClass(/dark/);

    await page.emulateMedia({ colorScheme: 'dark' });
    await page.reload();
    await expect(page.locator('html')).toHaveClass(/dark/);
  });

  test('explicit Dark persists and is server-rendered from the cookie', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/login');
    await expect(page.locator(TOGGLE)).toBeVisible();

    await page.click(opt('dark'));
    await expect(page.locator('html')).toHaveClass(/dark/);
    await expect(page.locator(opt('dark'))).toHaveAttribute('aria-checked', 'true');

    const cookie = (await page.context().cookies()).find((c) => c.name === 'forseti_theme');
    expect(cookie?.value).toBe('dark');

    // Reload on a light OS — the dark class must still be present, proving the
    // server rendered it from the cookie (not just client JS).
    await page.reload();
    await expect(page.locator('html')).toHaveClass(/dark/);

    // Raw request with the cookie: the HTML itself carries class="...dark...".
    const res = await page.request.get('/login');
    expect(await res.text()).toMatch(/<html[^>]*class="[^"]*dark/);
  });

  test('explicit Light overrides a dark OS', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/login');
    await page.click(opt('light'));
    await expect(page.locator('html')).not.toHaveClass(/dark/);
    await page.reload();
    await expect(page.locator('html')).not.toHaveClass(/dark/);
  });

  test('System mode follows the OS colour scheme', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/login');
    await page.click(opt('system'));
    await expect(page.locator('html')).not.toHaveClass(/dark/);

    // Re-resolve against a dark OS via reload — the pre-paint resolver is the
    // reliable cross-browser path (emulateMedia doesn't always dispatch the
    // matchMedia 'change' event to live listeners).
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.reload();
    await expect(page.locator('html')).toHaveClass(/dark/);
  });

  test('control is present on the authenticated chrome (base.html)', async ({ page }) => {
    await registerUser(page, 'playwright-theme');
    // Registration may land on /verification (card.html); navigate to the
    // dashboard explicitly so we assert against the base.html chrome.
    await page.goto('/');
    await expect(page.locator(TOGGLE)).toBeVisible();
  });
});
