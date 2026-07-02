# Onboarding surface (claim_email and invite templates)

# Claim email (claim_email.html)
claim-page-title = Claim email
claim-card-title = Claim email address
claim-subtitle = If someone registered your email but never verified it, you can take ownership by confirming you receive mail on this address.
claim-email-label = Email
claim-send-code = Send code
claim-changed-mind = Changed your mind?
claim-back-to-signup = Back to sign up

# Confirm claim (claim_email_confirm.html)
claim-confirm-page-title = Confirm claim
claim-confirm-card-title = Confirm your code
claim-confirm-subtitle = Enter the 6-digit code we just sent. Codes expire after 15 minutes.
claim-confirm-code-label = Code
claim-confirm-button = Confirm
claim-confirm-no-code = Didn't get a code?
claim-confirm-start-over = Start over

# Accept invite (invite/accept.html)
invite-accept-page-title = Accept invite
invite-accept-heading = Join { $org }
invite-accept-body = You've been invited to join { $org } as { $role }. The invite was sent to { $email }.

# Invite unavailable (invite/invalid.html)
invite-invalid-page-title = Invite unavailable
invite-invalid-heading = Invite unavailable
invite-invalid-contact = Contact the person who invited you to request a fresh link.
invite-invalid-back = Back to dashboard

# Claim-email flow errors (set in Rust)
claim-error-invalid-email = Enter a valid email address.
claim-error-code-expired = The code has expired. Start over.
claim-error-invalid-token = Invalid token. Start over.
claim-error-service-unavailable = Service temporarily unavailable. Try again in a moment.
claim-error-too-many-attempts = Too many wrong codes. Start over.
claim-error-code-mismatch = Code didn't match. Try again.
claim-error-no-longer-claimable = This email can no longer be claimed.
claim-error-release-failed = We couldn't release the email. Contact support.

# Invite finalize (set in Rust)
invite-error-corrupt = Invitation is corrupt. Contact your administrator.
