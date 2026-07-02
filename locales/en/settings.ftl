settings-hub-title = Settings
settings-hub-subtitle = Manage your account preferences, security settings, and active sessions.
settings-hub-profile-title = Profile
settings-hub-profile-desc = Update your email address and display name.
settings-hub-profile-link = Manage profile
settings-hub-password-title = Password
settings-hub-password-desc = Change your account password.
settings-hub-password-link = Change password
settings-hub-2fa-title = Two-factor auth
settings-hub-2fa-desc = Set up TOTP, recovery codes, and security keys.
settings-hub-2fa-link = Manage 2FA
settings-hub-sessions-title = Active sessions
settings-hub-sessions-desc = Review devices logged into your account.
settings-hub-sessions-link = View sessions
settings-hub-apps-title = Authorized apps
settings-hub-apps-desc = Review and revoke OAuth apps you've granted access to.
settings-hub-apps-link = Manage apps
settings-hub-providers-title = Linked providers
settings-hub-providers-desc = Connect or remove third-party sign-in providers.
settings-hub-providers-link = Manage providers
settings-hub-account-title = Account
settings-hub-account-desc = Permanent changes: delete your account.
settings-hub-account-link = Danger zone
settings-nav-general = General
settings-nav-security = Security
settings-nav-connections = Connections
settings-nav-overview = Overview
settings-nav-profile = Profile
settings-nav-organization = Organization
settings-nav-password = Password
settings-nav-2fa = 2FA
settings-nav-sessions = Sessions
settings-nav-offline = Offline login
settings-nav-authorized-apps = Authorized apps
settings-nav-linked-providers = Linked providers
settings-nav-account = Account

# Profile sub-page
settings-profile-heading = Profile
settings-profile-subtitle = Update your email address and display name.
settings-profile-email-not-verified = Not verified
settings-profile-email-send-verification = Send verification email
settings-profile-public-heading = Public profile
settings-profile-public-saved = Profile saved.
settings-profile-public-label-bio = Bio
settings-profile-public-label-location = Location
settings-profile-public-label-pronouns = Pronouns
settings-profile-public-label-website = Website
settings-profile-public-label-avatar = Avatar URL
settings-profile-public-avatar-hint = Optional. Leave blank to use the auto-generated identicon.
settings-profile-public-label-links = Links
settings-profile-public-save = Save profile
settings-profile-back = Back to settings
settings-profile-language-label = Preferred language
settings-profile-language-help = Applies across your devices.

# Password sub-page
settings-password-heading = Password
settings-password-subtitle = Change the password used to sign in.
settings-password-back = Back to settings

# Account sub-page
settings-account-heading = Account
settings-account-subtitle = Permanent changes to your account.
settings-account-delete-section-heading = Delete account
settings-account-delete-body = Permanently delete your account, every active session, and all 2FA / recovery state. Apps that hold copies of your data are notified so they can clear their side. This cannot be undone.
settings-account-delete-action = Delete my account

# Account delete confirmation page
settings-account-delete-page-title = Confirm delete
settings-account-delete-confirm-heading = Delete your account?
settings-account-delete-confirm-subtitle-prefix = This permanently removes
settings-account-delete-confirm-subtitle-suffix = and every session, recovery code, and credential attached to it.
settings-account-delete-apps-heading = These apps will be told you're gone
settings-account-delete-apps-note = Apps copy data they need (profile, settings) and keep it linked to your account ID. We notify them via the deletion webhook they registered so they can clear their copy.
settings-account-delete-no-apps = No third-party apps have copies of your data right now. Nothing to notify.
settings-account-delete-confirm-label = To confirm, type your email below:
settings-account-delete-confirm-placeholder = Type your email to confirm
settings-account-delete-confirm-submit = Yes, delete my account
settings-account-delete-confirm-cancel = Cancel

# Offline access sub-page
settings-offline-heading = Offline host login
settings-offline-subtitle = Set a dedicated passphrase that lets you log in at the terminal of an enrolled Linux host when it can't reach this server. It's separate from your account password. Use something you'll remember but wouldn't reuse.
settings-offline-status-set-prefix = An offline passphrase is
settings-offline-status-set-word = set
settings-offline-status-set-suffix = . Enter a new one below to change it, or remove it entirely.
settings-offline-status-unset = No offline passphrase is set yet. Without one, you can't log in to an enrolled host while it's offline.
settings-offline-label-new-passphrase = New offline passphrase
settings-offline-label-passphrase = Offline passphrase
settings-offline-passphrase-hint = At least { $min_len } characters. Don't reuse your account password.
settings-offline-action-change = Change passphrase
settings-offline-action-set = Set passphrase
settings-offline-remove-heading = Remove offline access
settings-offline-remove-body = Delete your offline passphrase. Enrolled hosts drop it on their next sync, and you'll no longer be able to log in to them while they're offline.
settings-offline-action-remove = Remove passphrase
settings-offline-back = Back to settings

# Password handoff (recovery → set-new-password)
settings-handoff-heading = Set a new password
settings-handoff-subtitle = You're signed in via the recovery code. Pick a new password to finish.
settings-handoff-countdown-label = Time remaining to set your new password:
settings-handoff-sign-out = Sign out without changing

# 2FA sub-page
settings-2fa-heading = Two-factor authentication
settings-2fa-subtitle = Strengthen your account with a second factor.
settings-2fa-no-recovery-warning-heading = No recovery codes: you risk being locked out
settings-2fa-no-recovery-warning-body = Two-factor authentication is on, but you have no recovery codes. If you lose your authenticator or security key, recovery codes are the only way back into your account. Generate them now.
settings-2fa-no-recovery-warning-action = Generate codes
settings-2fa-totp-heading = Authenticator app (TOTP)
settings-2fa-totp-desc = Use an app like 1Password, Bitwarden, Aegis, or Authy to generate 6-digit codes.
settings-2fa-totp-enabled = Enabled
settings-2fa-totp-scan-hint = Scan this QR code with your authenticator app, or enter the secret manually:
settings-2fa-totp-not-offered = Authenticator-app setup is not currently offered by your server.
settings-2fa-recovery-heading = Recovery codes
settings-2fa-recovery-desc = One-time codes that let you sign in if you lose access to your authenticator.
settings-2fa-recovery-active = Active
settings-2fa-recovery-save-strong = Save these now.
settings-2fa-recovery-save-suffix = They will not be shown again. Store them somewhere safe. A password manager works well.
settings-2fa-recovery-not-offered = Recovery codes are not currently offered by your server.
settings-2fa-webauthn-heading = Security keys & passkeys
settings-2fa-webauthn-desc = Use a hardware key (YubiKey, Titan) or a platform passkey (Touch ID, Windows Hello) as your second factor.
settings-2fa-webauthn-remove-fallback = Remove security key
settings-2fa-webauthn-not-enabled = Passkey support is not enabled by your administrator.
settings-2fa-back = Back to settings

# Sessions sub-page
settings-sessions-heading = Active sessions
settings-sessions-subtitle = Devices currently signed into your account. Revoke any you don't recognise.
settings-sessions-revoke-action = Sign out
settings-sessions-revoke-others-heading = Sign out of all other devices
settings-sessions-revoke-others-desc = Keeps this session active and revokes every other one.
settings-sessions-revoke-others-action = Sign out others
settings-sessions-back = Back to settings

# Authorized apps sub-page
settings-apps-heading = Authorized apps
settings-apps-subtitle = Apps you've granted access to your account. Revoke any you no longer use. They'll have to ask for permission again next time you sign in.
settings-apps-empty = No apps have been granted access to your account yet.
settings-apps-verified-label = Verified
settings-apps-access-granted-prefix = Access granted
settings-apps-revoke-action = Revoke access
settings-apps-back = Back to settings
settings-apps-reviewed-title = Reviewed by your administrator

# 2FA leftovers
settings-2fa-qr-alt = TOTP QR code

# Password handoff countdown-expiry (rendered into JS)
settings-handoff-expired-lead = Your recovery window expired.
settings-handoff-expired-link = Start again

# Linked providers sub-page
settings-providers-heading = Linked providers
settings-providers-subtitle = Sign in to your account using a third-party identity provider.
settings-providers-empty-heading = No upstream providers configured by your administrator.
settings-providers-empty-desc = Contact your administrator to enable Google, GitHub, or other sign-in providers.
settings-providers-back = Back to settings

# Inline-code splits (item 8: 2+ code elements per string)

# settings_profile.html - public profile description (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Visible to org-mates on your
settings-profile-public-desc-part2 = page and to apps you grant the
settings-profile-public-desc-part3 = or
settings-profile-public-desc-part4 = OAuth scopes. Leave any field blank to hide it.

# settings_profile.html - links hint (code: Label|https://url)
settings-profile-links-hint-part1 = One per line, in the format
settings-profile-links-hint-part2 = .

# Flash messages and inline error bodies set in Rust handlers.
flash-session-signed-out = Session signed out.
flash-session-signout-failed = Could not sign out that session.
flash-sessions-signed-out-others =
    { $count ->
        [one] Signed out { $count } other session.
       *[other] Signed out { $count } other sessions.
    }
flash-sessions-signout-others-failed = Could not sign out other sessions.
flash-app-access-revoked = Access revoked.
flash-app-access-revoke-failed = Could not revoke access for that application.
flash-offline-passphrase-saved = Offline passphrase saved. Enrolled hosts will pick it up on their next sync.
flash-offline-passphrase-save-failed = Could not save your offline passphrase. Please try again.
flash-offline-passphrase-too-short = Your offline passphrase must be at least { $min_len } characters.
flash-offline-passphrase-removed = Offline passphrase removed. Hosts will drop it on their next sync.
flash-offline-passphrase-none = You don't have an offline passphrase set.
flash-offline-passphrase-remove-failed = Could not remove your offline passphrase. Please try again.
settings-profile-url-invalid = Website and avatar URL must be valid http:// or https:// URLs.
settings-profile-link-url-invalid = Every link URL must be a valid http:// or https:// URL.
settings-save-failed = We couldn't save your changes. Please try again.
