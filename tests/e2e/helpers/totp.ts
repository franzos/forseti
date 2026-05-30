// TOTP code generation from a base32-encoded shared secret. The portal
// (via Kratos) uses RFC 6238 defaults: SHA1, 30s period, 6 digits.
// `otplib` honours those defaults out of the box.
import { authenticator } from 'otplib';

authenticator.options = { digits: 6, step: 30, algorithm: 'sha1' };

/**
 * Compute the current TOTP code from a base32-encoded secret. Kratos
 * rejects code reuse, so each call must produce a fresh code — never
 * cache the return value across test steps.
 */
export function computeTotp(secretBase32: string): string {
  return authenticator.generate(secretBase32);
}
