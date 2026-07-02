# Login page
auth-login-page-title = Sign in
auth-login-card-title = Sign in to your account
auth-login-card-subtitle = Welcome back to { $brand }.
auth-login-aal2-body = This area requires two-factor authentication, but your account doesn't have a second factor set up yet.
auth-login-aal2-hint = Set up an authenticator app, security key, or recovery codes in settings, then come back.
auth-login-aal2-setup-link = Set up two-factor authentication
auth-login-forgot-password = Forgot password?
auth-login-no-account = Don't have an account?
auth-login-create-account = Create account

# Shared divider (login + registration)
auth-or-continue-with = Or continue with

# Registration page
auth-registration-page-title = Create account
auth-registration-card-title = Create an account
auth-registration-card-subtitle = Sign up to manage your identity securely.
auth-registration-have-account = Already have an account?
auth-registration-sign-in-link = Sign in
auth-registration-claim-body = If this is your email and you never finished signing up,
auth-registration-claim-link = claim it

# Recovery page
auth-recovery-page-title = Account recovery
auth-recovery-card-title-sent = Check your email
auth-recovery-card-title-default = Forgot your password?
auth-recovery-card-subtitle-sent = We sent a recovery code to your inbox. Enter it below to continue.
auth-recovery-card-subtitle-default = Enter your email and we'll send you a link to reset it.
auth-recovery-back-to-sign-in = Back to sign in

# Verification page
auth-verification-page-title = Verify your email
auth-verification-card-title-passed = Email verified
auth-verification-card-title-sent = Check your email
auth-verification-card-title-default = Verify your email
auth-verification-card-subtitle-passed = Your email has been confirmed. You can close this tab or continue.
auth-verification-card-subtitle-sent = We sent a verification code to your inbox. Enter it below to confirm.
auth-verification-card-subtitle-default = Enter your email to receive a verification code.
auth-verification-sent-email-hint = Use the code from the most recent verification email, or open the link in that email instead of typing the code by hand.
auth-verification-back-to-dashboard = Back to dashboard
auth-verification-back-to-sign-in = Back to sign in

# WebAuthn / passkey browser-side strings (embedded via data attributes in webauthn_helper.html)
auth-webauthn-no-support = Your browser does not support WebAuthn / passkeys.
auth-passkey-needs-platform = Passkey sign-in needs a platform credential on this device (Touch ID, Windows Hello, an Android device, or a synced passkey). Your browser does not have one set up.
auth-webauthn-err-not-allowed = The credential request was cancelled, timed out, or no matching credential was available.
auth-webauthn-err-security = Your browser refused the security operation. Check that the site is loaded over a trusted origin and the registered identifier matches.
auth-webauthn-err-invalid-state = A credential is already registered with this device. Try signing in instead, or use a different device.
auth-webauthn-err-not-supported = Your browser does not support the requested credential parameters.
auth-webauthn-err-abort = The credential request was aborted before it completed.
auth-webauthn-err-generic-prefix = Authenticator error:

# Flow field labels. Kratos emits trait fields with the schema `title` under the
# generic passthrough label id 1070002; flow_view.rs overrides these by name.
auth-field-email = E-Mail
auth-field-first-name = First Name
auth-field-last-name = Last Name
