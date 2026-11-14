// TOTP code generation from a base32-encoded shared secret. The portal
// (via Kratos) uses RFC 6238 defaults: SHA1, 30s period, 6 digits.
// `otplib` honours those defaults out of the box.
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authenticator } from 'otplib';
import { isNative } from './identity';

authenticator.options = { digits: 6, step: 30, algorithm: 'sha1' };

const STEP_MS = 30_000;
// Shared by the global setup and the worker processes of one container run.
const LAST_STEP_FILE = join(tmpdir(), 'forseti-e2e-totp-last-step');

/**
 * Compute the current TOTP code from a base32-encoded secret. Kratos
 * rejects code reuse, so each call must produce a fresh code — never
 * cache the return value across test steps.
 */
export function computeTotp(secretBase32: string): string {
  return authenticator.generate(secretBase32);
}

function lastUsedStep(): number {
  try {
    return Number(readFileSync(LAST_STEP_FILE, 'utf8')) || 0;
  } catch {
    return 0;
  }
}

/**
 * A TOTP code the server will accept. The native backend rejects a second code
 * for the same identity within one 30 s step (RFC 6238 section 5.2), so on
 * native this waits for the next step when the current one was already used.
 * Kratos accepts replays: plain {@link computeTotp}.
 */
export async function freshTotp(secretBase32: string): Promise<string> {
  if (!isNative) return computeTotp(secretBase32);
  for (;;) {
    const step = Math.floor(Date.now() / STEP_MS);
    if (lastUsedStep() < step) {
      writeFileSync(LAST_STEP_FILE, String(step));
      return authenticator.clone({ epoch: step * STEP_MS }).generate(secretBase32);
    }
    await new Promise((r) => setTimeout(r, (step + 1) * STEP_MS - Date.now() + 100));
  }
}
