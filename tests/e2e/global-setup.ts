// Native only: sign the admin in once (password + TOTP) and save the session
// to `ADMIN_STATE`, which `signInAdminAal2` hands to every spec. The native
// TOTP replay guard accepts one code per identity per 30 s step, so per-spec
// sign-ins would stall the suite.
import { chromium, type FullConfig } from '@playwright/test';
import { adminCredsFromEnv, signInAdminWithTotp } from './helpers/admin';
import { ADMIN_STATE, isNative } from './helpers/identity';

export default async function globalSetup(config: FullConfig): Promise<void> {
  const creds = adminCredsFromEnv();
  if (!isNative || !creds) return;
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ baseURL: config.projects[0]?.use.baseURL });
    const page = await context.newPage();
    await signInAdminWithTotp(page, creds);
    await context.storageState({ path: ADMIN_STATE });
  } finally {
    await browser.close();
  }
}
