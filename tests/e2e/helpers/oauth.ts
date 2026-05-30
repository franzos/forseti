// OAuth helpers: PKCE (S256) + a JWT segment decoder. Kept dependency-free
// (Node's built-in `crypto` does both jobs) so the package surface stays
// `@playwright/test` + `otplib` only.
import { createHash, randomBytes } from 'node:crypto';

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

/** RFC 7636 PKCE pair: 32-byte verifier, SHA-256 challenge. */
export function generatePkcePair(): PkcePair {
  const verifier = base64UrlEncode(randomBytes(32));
  const challenge = base64UrlEncode(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

/** Decode a JWT's claims (no signature check — we trust Hydra issued it). */
export function decodeJwtClaims(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error(`not a JWT: ${jwt.slice(0, 40)}…`);
  const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(
    'utf8',
  );
  return JSON.parse(json) as Record<string, unknown>;
}
