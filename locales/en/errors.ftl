# Error page
error-reference-id = Reference ID:
error-cta-back-to-sign-in = Back to sign in

# OAuth logout confirmation
logout-card-title = Sign out of all apps?
logout-card-subtitle = This will end your session with { $brand } and notify every app you signed in to.
logout-body-text = The app that asked you to sign out will be told the request is complete. Some apps may keep local data cached for a short while; signing out here ends the session at { $brand }.
logout-action-sign-out = Sign out
logout-action-cancel = Cancel

# Admin dialog titles and bodies used by render_admin_error at call sites that have a locale.
# Call sites without a locale (helper functions, error boundaries) keep their English literals.
dialog-identity-unavailable-title = Identity unavailable
dialog-identity-unavailable-body = We couldn't load that identity. It may have been deleted.
dialog-recovery-code-failed-title = Recovery code failed
dialog-recovery-code-failed-body = We minted the recovery code but couldn't stage it for one-shot display. Generate a fresh code to retry.
dialog-disable-failed-title = Disable failed
dialog-enable-failed-title = Enable failed
dialog-delete-failed-title = Delete failed
dialog-revoke-failed-title = Revoke failed

# Error boundary (error_boundary.html), title/body/cta set in Rust handlers.
error-boundary-auth-unavailable-title = Authentication unavailable
error-boundary-auth-unavailable-body = We couldn't reach the authentication service. Please try again in a moment.
error-boundary-cta-try-again = Try again
error-boundary-cta-sign-in = Sign in
error-boundary-cta-back-to-settings = Back to settings
error-boundary-cta-back-to-dashboard = Back to dashboard
error-boundary-cta-back-to-account = Back to account
error-boundary-signin-title = Sign-in unavailable
error-boundary-signup-title = Sign-up unavailable
error-boundary-recovery-title = Recovery unavailable
error-boundary-verification-title = Verification unavailable
error-boundary-settings-title = Settings unavailable
error-boundary-logout-title = Logout unavailable
error-boundary-logout-body = We couldn't complete your logout because the authentication service is unreachable. Your session is still active, so please try again in a moment.
error-boundary-sessions-title = Sessions unavailable
error-boundary-sessions-body = We couldn't list your active sessions. Please try again in a moment.
error-boundary-authorized-apps-title = Authorized apps unavailable
error-boundary-authorized-apps-no-session-body = We couldn't read your session. Please sign in again.
error-boundary-authorized-apps-service-body = We couldn't reach the OAuth service. Please try again in a moment.
error-boundary-account-deletion-title = Account deletion failed
error-boundary-account-delete-bad-session = Your session is in an unexpected state. Please sign in again and retry.
error-boundary-account-delete-sole-owner = You're the only owner of { $names }. Transfer ownership to another member before deleting your account.
error-boundary-account-delete-ownership-check-failed = We couldn't verify your organization ownership. Nothing was changed; please try again in a moment.
error-boundary-account-delete-consent-unreachable = We couldn't reach the consent service to notify your connected apps. Nothing was changed; please try again in a moment.
error-boundary-account-delete-notifications-failed = We couldn't prepare the delete notifications. Nothing was changed; please try again.
error-boundary-account-delete-failed = We couldn't delete your account. Please try again in a moment.

# SAML error boundary (rendered under the default locale; the ACS callback carries no request locale).
error-boundary-sso-unavailable-title = Single sign-on unavailable
error-boundary-sso-unavailable-body = Single sign-on isn't available for this address. Check the link your administrator gave you, or sign in with your usual method.
error-boundary-sso-failed-title = Single sign-on failed
error-boundary-sso-validation-failed-body = This sign-on attempt couldn't be validated. Start again from your organization's SSO link.
error-boundary-sso-upstream-failed-body = The sign-on service is temporarily unavailable. Please try again.
error-boundary-sso-no-email-body = The identity provider didn't supply an email address. Ask your administrator to map the email attribute on the SAML connection.

# Kratos self-service error page (error.html), fallbacks set in Rust.
error-page-generic-title = Something went wrong
error-page-generic-body = We couldn't load the requested page. The link may have expired or been used already.
error-page-link-expired-title = Link expired
error-page-link-expired-body = This link is no longer valid. Please start again from sign-in.
error-page-security-title = Security check failed
error-page-already-signed-in-title = Already signed in
error-page-default-message = We couldn't complete that request.

# Admin gate forbidden page (admin/forbidden.html), set in Rust.
error-admin-access-denied-title = Access denied
error-admin-access-denied-body = Your account isn't authorised to use the admin tools.
error-admin-access-denied-forseti-body = Your account isn't authorised to use the Forseti-wide admin tools.
error-admin-access-denied-org-body = You don't have admin access to that organization.

# SAML blocked
error-saml-blocked-page-title = Sign-on blocked
error-saml-blocked-card-title = We couldn't sign you in
error-saml-unverified-prefix = An account for
error-saml-unverified-suffix = already exists but its email address hasn't been verified, so single sign-on can't safely attach to it. Verify the address from your original sign-up email, or ask your administrator for help.
error-saml-cross-org-not-member = Your account isn't a member of this organization yet. Ask your administrator to add you, then try again.
error-saml-conflict = We couldn't sign you in. Please contact your administrator.
error-saml-blocked-cta = Go to sign in
