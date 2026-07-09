// Admin-driven OAuth client creation. Extracted from Scenario B so the
// RP-initiated-logout (E) and self-delete (G) scenarios use the same
// `/admin/clients/new?type=web_app` form-fill path. Keep this helper
// dumb: it just fills the visible inputs and submits. Caller is
// responsible for the admin session (`signInAdminAal2` before this).
import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

export interface CreatedClient {
  clientId: string;
  clientSecret: string;
}

export interface CreateClientOpts {
  name: string;
  redirectUri: string;
  /** Space-separated scope list. Defaults to the common openid set. */
  scope?: string;
  /** Adds RP-initiated-logout post-logout redirect URIs to the textarea. */
  postLogoutRedirectUris?: string[];
  /** Sets the `account_deletion_url` field (Scenario G). */
  accountDeletionUrl?: string;
  /** Default: false — leave consent enabled so the user can click Allow. */
  skipConsent?: boolean;
}

/**
 * Drive `/admin/clients/new?type=web_app` to create a fresh OAuth client.
 * Returns `{ clientId, clientSecret }` parsed from the show page's
 * "Credentials: shown once" reveal block.
 *
 * Pre-requisite: the page must already be signed in at AAL2 — call
 * `signInAdminAal2(page, creds)` first.
 */
export async function createOAuthClient(
  page: Page,
  opts: CreateClientOpts,
): Promise<CreatedClient> {
  await page.goto('/admin/clients/new?type=web_app');

  await page.locator('input[name="name"]').fill(opts.name);
  await page.locator('textarea[name="redirect_uris"]').fill(opts.redirectUri);
  await page
    .locator('input[name="scope"]')
    .fill(opts.scope ?? 'openid email profile offline_access');

  if (opts.postLogoutRedirectUris && opts.postLogoutRedirectUris.length > 0) {
    await page
      .locator('textarea[name="post_logout_redirect_uris"]')
      .fill(opts.postLogoutRedirectUris.join('\n'));
  }
  if (opts.accountDeletionUrl) {
    await page.locator('input[name="account_deletion_url"]').fill(opts.accountDeletionUrl);
  }

  // skip_consent defaults to true on some presets; force whichever state
  // the caller asked for. Default: unchecked (we WANT the consent page).
  const skipConsent = page.locator('input[name="skip_consent"]');
  const wantSkip = opts.skipConsent === true;
  if ((await skipConsent.isChecked()) !== wantSkip) {
    if (wantSkip) await skipConsent.check();
    else await skipConsent.uncheck();
  }

  await Promise.all([
    page.waitForURL(/\/admin\/clients\/[a-f0-9-]+/),
    page.locator('form[action="/admin/clients"] button[type="submit"]').click(),
  ]);

  const clientId = page.url().match(/\/admin\/clients\/([a-f0-9-]+)/)?.[1];
  if (!clientId) throw new Error(`could not parse client_id from ${page.url()}`);

  const revealHeader = page.getByText('Credentials: shown once');
  await revealHeader.waitFor();
  // The secret is in the first leaf `<pre>` directly after the header —
  // same selector strategy as Scenario B.
  const clientSecret = await page
    .locator('pre')
    .filter({ hasNot: page.locator(':scope > *') })
    .first()
    .innerText();
  expect(clientSecret).toMatch(/^\S{20,}$/);

  return { clientId, clientSecret };
}
