# User Guide

For people using an account on a site that runs Forseti. You don't need to install or configure anything; this covers the self-service pages you'll see when you sign in, create an account, or manage your profile. If you run the service, see the [operator guide](./operator-guide.md); if you're building an app against it, see the [integration guide](./integration-guide.md).

## Signing in

Enter your email and password on the login page. If the site has other sign-in methods enabled (a social or enterprise login), you'll see them as buttons on the same page. After signing in you're returned to the app you came from.

Some apps route you into a specific organization when you sign in. If you're not already a member, you may see a one-time "Join `<Org>`?" page asking you to confirm before you continue; you can also choose to continue without joining. You won't be asked again once you've joined.

## Creating an account

The registration page asks for your email and a password, plus whatever profile fields the operator has configured. Some sites verify your email address before the account is fully active; if so, you'll get a message with a link or code to confirm.

## Recovering access

If you've forgotten your password, use the "forgot password" link on the login page. You'll receive a recovery link or code by email, then get to set a new password. Recovery is rate-limited, so if a message doesn't arrive, wait a moment before trying again.

## Two-factor authentication (2FA)

From your account settings you can turn on a second factor for extra protection. The usual option is an authenticator app (TOTP): scan the QR code, enter the six-digit code to confirm, and save the recovery codes somewhere safe. After that, sign-in asks for a code from your app in addition to your password.

## Managing your account

The account settings pages let you update your profile and email, change your password, manage your 2FA methods, and review or end active sessions.

## Connected apps and consent

When an app asks to use your account, you'll see a consent screen listing what it wants access to. You can approve or decline. Sites that support it let you review and revoke previously connected apps from your account settings.

## Signing out

Use the sign-out option to end your session. Depending on how the site is set up, this may also sign you out of the connected apps you reached through it.
