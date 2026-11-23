// Chromium virtual authenticators through CDP, for the native WebAuthn specs.
// WebAuthn needs a secure context whose host is the RP ID, so these specs run
// against `localhost:3000` (`make e2e-native`), not `host.containers.internal`.
import type { CDPSession, Page } from '@playwright/test';

/** A virtual authenticator attached to one page's CDP session. */
export interface VirtualAuthenticator {
  cdp: CDPSession;
  authenticatorId: string;
}

// One CDP session per page: the virtual authenticators live as long as it does.
const sessions = new WeakMap<Page, Promise<CDPSession>>();

function session(page: Page): Promise<CDPSession> {
  let cdp = sessions.get(page);
  if (!cdp) {
    cdp = page
      .context()
      .newCDPSession(page)
      .then(async (s) => {
        await s.send('WebAuthn.enable');
        return s;
      });
    sessions.set(page, cdp);
  }
  return cdp;
}

async function attach(
  page: Page,
  options: {
    transport: 'internal' | 'usb';
    hasResidentKey: boolean;
    hasUserVerification: boolean;
  },
): Promise<VirtualAuthenticator> {
  const cdp = await session(page);
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ...options,
      isUserVerified: options.hasUserVerification,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/**
 * A platform authenticator holding discoverable, user-verified credentials.
 * Attach it before the page loads: `webauthn_helper.html` disables passkey
 * buttons when no platform authenticator is reported at load time.
 */
export function addPasskeyAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  return attach(page, { transport: 'internal', hasResidentKey: true, hasUserVerification: true });
}

/** A roaming USB key: no resident keys, presence only. */
export function addSecurityKeyAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  return attach(page, { transport: 'usb', hasResidentKey: false, hasUserVerification: false });
}

/** Detach `authenticator`, so the next ceremony goes to another one. */
export async function removeAuthenticator(authenticator: VirtualAuthenticator): Promise<void> {
  await authenticator.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authenticator.authenticatorId,
  });
}

/** How many credentials `authenticator` holds. */
export async function credentialCount(authenticator: VirtualAuthenticator): Promise<number> {
  const { credentials } = await authenticator.cdp.send('WebAuthn.getCredentials', {
    authenticatorId: authenticator.authenticatorId,
  });
  return credentials.length;
}
