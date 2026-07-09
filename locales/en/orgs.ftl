# Shared field labels used across organisation pages
orgs-field-name = Name
orgs-field-slug = Slug
orgs-field-email = Email
orgs-field-role = Role

# Organisation switcher (top-nav dropdown)
orgs-switcher-label = Switch organization
orgs-switcher-manage-link = Manage organizations

# Organisation list (list.html)
orgs-list-title = Organizations
orgs-list-heading = Your organizations
orgs-list-create-heading = Create a new organization
orgs-list-field-slug-optional = Slug (optional)
orgs-list-action-create = Create
orgs-list-field-access-mode = Access mode
orgs-list-mode-internal-title = Internal
orgs-list-mode-internal-body = Invite-only. Members join by invite (and, later, a verified company domain).
orgs-list-mode-external-title = External
orgs-list-mode-external-body = Public self-serve sign-up. Member directory is locked to administrators only.
orgs-list-tier-gate-heading = Multiple organizations is a { $tier } feature
orgs-list-license-missing = Your current license doesn't include the Organizations feature.
orgs-list-unlicensed = This { $brand } install is running unlicensed, so additional organizations beyond the default are gated.
orgs-list-license-upgrade = Activate or upgrade a license to create more.
orgs-list-link-get-license = Get a license
orgs-list-link-activate-license = Activate an existing license

# Organisation overview - owner view (overview.html)
orgs-overview-subtitle-default = This is the default organization for this { $brand } install. Anyone who signs up joins it automatically.
orgs-overview-subtitle = Manage this organization's settings, branding, and membership.
orgs-overview-identity-heading = Identity
orgs-overview-quicklinks-heading = Quick links
orgs-link-branding = Branding
orgs-link-members = Members
orgs-link-teams = Teams
orgs-link-domains = Domains
orgs-sso-heading = Enterprise SSO
orgs-sso-status-enabled = enabled
orgs-sso-status-disabled = disabled
orgs-sso-operator-note = SSO connections are managed by the operator.
orgs-access-mode-heading = Access mode
orgs-access-mode-label = Mode
orgs-access-mode-internal = Internal
orgs-access-mode-external = External
orgs-access-mode-note-default = The default organization is always internal.
orgs-access-mode-note-internal = Members join by invite. Switching to external enables public sign-up.
orgs-access-mode-note-external = Public sign-up is enabled. The member directory is locked to administrators only while external.
orgs-access-mode-action-switch-external = Switch to external
orgs-access-mode-action-switch-internal = Switch to internal
orgs-confirm-switch-external = Switch to external? This enables the public sign-up page and restricts the member directory to administrators only.
orgs-confirm-switch-internal = Switch to internal? This disables the public sign-up page. Existing members keep their membership.
orgs-danger-heading = Danger zone
orgs-danger-delete-body = Hard-delete this organization. Forseti refuses if any OAuth2 clients are still associated.
orgs-danger-delete-action = Delete organization
orgs-confirm-delete-org = Delete { $name }? This cannot be undone.

# Organisation overview - non-owner view (overview_info.html)
orgs-info-subtitle-default = This is the default organization for this { $brand } install. You're a member.
orgs-info-subtitle = You're a member of this organization.
orgs-info-org-heading = Organization
orgs-info-members-label = Members
orgs-info-managed-by-heading = Managed by
orgs-info-managed-by-note = Contact an owner for changes to org name, branding, or membership.

# Members page (members.html)
orgs-members-page-heading = Members
orgs-members-subtitle = Owners can promote / demote members and remove anyone except the last owner.
orgs-members-visibility-note-admins-only = Only administrators can see the full member list.
orgs-members-visibility-note-same-group = You see members who share a team with you.
orgs-members-visibility-note-all = All members are visible.
orgs-members-invite-heading = Invite by email
orgs-members-role-member = Member
orgs-members-role-owner = Owner
orgs-members-action-invite = Send invite
orgs-members-visibility-heading = Directory visibility
orgs-members-visibility-label = Who can see the member list
orgs-members-visibility-opt-all = All members
orgs-members-visibility-opt-same-group = Same team only
orgs-members-visibility-opt-admins-only = Administrators only
orgs-members-visibility-hint = Same team only requires at least one team to exist first.
orgs-members-col-joined = Joined
orgs-members-badge-you = you
orgs-members-badge-hidden = Hidden
orgs-members-action-show = Show
orgs-members-action-hide = Hide
orgs-members-action-update = Update
orgs-members-action-remove = Remove
orgs-confirm-remove-member = Remove { $email }?
orgs-members-invites-heading = Pending invites
orgs-members-invites-col-sent = Sent
orgs-members-invites-col-expires = Expires

# Teams page (teams.html)
orgs-teams-page-heading = Teams
orgs-teams-subtitle = Group members into teams. Teams scope host access and drive same-team directory visibility.
orgs-teams-create-heading = Create a team
orgs-teams-action-create = Create team
orgs-teams-col-team = Team
orgs-teams-col-members = Members
orgs-teams-action-rename = Rename
orgs-teams-action-manage-members = Manage members
orgs-teams-action-delete = Delete
orgs-confirm-delete-team = Delete { $name }? This removes the team and its memberships.
orgs-teams-selected-heading = Members of { $team }
orgs-teams-add-member-label = Add member
orgs-teams-action-add = Add

# Domains page (domains.html)
orgs-domains-page-heading = Allowed domains
orgs-domains-subtitle = Users with a verified email at a proven domain join this organization automatically.
orgs-domains-add-heading = Add a domain
orgs-domains-field-domain = Domain
orgs-domains-field-method = Verification method
orgs-domains-method-http_file = HTTP file
orgs-domains-method-dns_txt = DNS TXT record
orgs-domains-method-email = Email
orgs-domains-action-add = Add domain
orgs-domains-col-domain = Domain
orgs-domains-col-method = Method
orgs-domains-col-status = Status
orgs-domains-status-verified = Verified
orgs-domains-status-pending = Pending
orgs-domains-instructions-http_file = Serve { $token } at https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = Create a TXT record at _forseti-verify.{ $domain } with value: { $token }
orgs-domains-instructions-email = A code was emailed to admin@{ $domain } and postmaster@{ $domain }. Paste it below.
orgs-domains-action-verify = Verify
orgs-domains-action-confirm = Confirm code
orgs-domains-field-token = Confirmation code
orgs-domains-action-remove = Remove
orgs-confirm-remove-domain = Remove { $domain }? Auto-join for this domain stops immediately.
orgs-domains-policy-heading = Join policy
orgs-domains-policy-subtitle = Choose how users with a verified email at a proven domain join this organization.
orgs-domains-policy-field = Policy
orgs-domains-policy-invite-only = Invite only
orgs-domains-policy-auto-join = Verified-domain users can self-join
orgs-domains-policy-save = Save policy

# Branding page (branding.html)
orgs-branding-page-heading = Branding
orgs-branding-subtitle-prefix = Override Forseti's default brand with this organization's logo and support email. Falls back to
orgs-branding-subtitle-infix = in
orgs-branding-subtitle-suffix = when unset.
orgs-branding-field-logo-url = Logo URL
orgs-branding-field-logo-file = Logo image (PNG, JPEG, or WebP; max 256 KB)
orgs-branding-logo-remove = Remove logo
orgs-branding-logo-save = Upload logo
orgs-branding-field-support-email = Support email
orgs-branding-theme-preset = Theme preset
orgs-branding-primary = Primary color
orgs-branding-on-primary = Text on primary
orgs-branding-secondary = Accent color
orgs-branding-request-public = Enable a public login page (/o/your-slug)
orgs-branding-preview = Preview

# Public landing page (public_landing.html)
orgs-public-landing-note = To sign in, open the application your team provided. Sign-in happens from there.
orgs-public-landing-register = Create an account

# Join confirm (join_confirm.html)
join-confirm-page-title = Join organization
join-confirm-heading = Join { $org }
join-confirm-body = You are joining { $org }. Continue?
join-confirm-cta = Join
join-confirm-register-cta = Register to join { $org }
