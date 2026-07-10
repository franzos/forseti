# Admin banner (admin_shell.html)
admin-banner-label = ADMIN
admin-banner-body = You're on a privileged surface. Actions here are audit-logged.

# Admin nav sidebar heading (admin_nav.html)
admin-nav-heading = Admin
admin-nav-subtitle = Operator tools

# Admin nav section headers
admin-nav-section-system = System
admin-nav-section-access = Access
admin-nav-section-linux = Linux

# Admin nav item labels
admin-nav-status = Status
admin-nav-configuration = Configuration
admin-nav-audit = Audit
admin-nav-webhooks = Webhooks
admin-nav-license = License
admin-nav-identities = Identities
admin-nav-sessions = Sessions
admin-nav-clients = OAuth2 clients
admin-nav-dcr-tokens = DCR tokens
admin-nav-saml = SAML SSO
admin-nav-hosts = Hosts
admin-nav-accounts = Accounts

# Identities list (identities_list.html)
admin-identities-page-title = Identities
admin-identities-subtitle = Kratos-managed identities and their state.
admin-identities-search-placeholder = Search by ID or email
admin-identities-search-button = Search
admin-identities-col-email = Email
admin-identities-col-state = State
admin-identities-col-created = Created
admin-identities-empty = No identities found.
admin-identities-prev = Back to start
admin-identities-next = Next page

# Identity detail (identity_show.html)
admin-identity-status-active = active
admin-identity-recovery-code-heading = Recovery code (shown once)
admin-identity-recovery-link-heading = Recovery link
admin-identity-recovery-note = Share this with the user over a trusted channel. It won't be shown again.
admin-identity-section-actions = Actions
admin-identity-action-generate-recovery = Generate recovery code
admin-identity-action-disable = Disable
admin-identity-action-enable = Enable
admin-identity-action-delete = Delete
admin-identity-section-traits = Traits
admin-identity-section-addresses = Verifiable addresses
admin-identity-addresses-empty = No verifiable addresses on this identity.
admin-identity-status-verified = verified
admin-identity-status-pending = pending
admin-identity-section-credentials = Credentials
admin-identity-credentials-empty = No credentials configured.
admin-identity-section-sessions = Recent sessions
admin-identity-sessions-empty = No session history.
admin-identity-action-revoke-session = Revoke session

# Identity picker (identity_picker.html)
admin-identity-picker-page-title = Select user
admin-identity-picker-subtitle = Pick an identity to continue.
admin-identity-picker-invalid-return = Invalid return target.
admin-identity-picker-search-placeholder = Search by ID or email
admin-identity-picker-search-button = Search
admin-identity-picker-col-email = Email
admin-identity-picker-col-state = State
admin-identity-picker-col-created = Created
admin-identity-picker-empty = No identities found.
admin-identity-picker-action-select = Select
admin-identity-picker-prev = Back to start
admin-identity-picker-next = Next page

# Sessions list (sessions_list.html)
admin-sessions-page-title = Sessions
admin-sessions-subtitle = Every session known to Kratos, across all identities.
admin-sessions-filter-active-only = Active sessions only
admin-sessions-col-identity = Identity
admin-sessions-col-authenticated = Authenticated
admin-sessions-col-expires = Expires
admin-sessions-col-device = Device
admin-sessions-empty = No sessions to show.
admin-sessions-action-revoke = Revoke
admin-sessions-prev = Back to start
admin-sessions-next = Next page

# Generic confirm dialog (confirm.html)
admin-confirm-cancel = Cancel

# Forbidden page (forbidden.html)
admin-forbidden-back = Back to dashboard

# Admin error page (error.html)
admin-error-back = Back to admin status

# Clients list (clients_list.html)
admin-clients-page-title = OAuth2 clients
admin-clients-subtitle = Hydra-registered relying parties.
admin-clients-action-new = New client
admin-clients-search-placeholder = Search by client name or ID
admin-clients-filter-all-types = All types
admin-clients-filter-all-verifications = All verifications
admin-clients-filter-verified = Verified
admin-clients-filter-unverified = Unverified
admin-clients-search-button = Search
admin-clients-col-name = Name
admin-clients-col-type = Type
admin-clients-col-grants = Grants
admin-clients-col-created = Created
admin-clients-badge-unverified-title = Not vetted by an administrator
admin-clients-badge-self-registered = Self-registered
admin-clients-badge-self-registered-title = Registered via /oauth2/register (RFC 7591)
admin-clients-empty = No clients registered.
admin-clients-prev = Back to start
admin-clients-next = Next page

# Client shared badges (clients_list.html, client_show.html)
admin-client-badge-verified = Verified
admin-client-badge-unverified = Unverified
admin-client-badge-unverified-title = An administrator has not vetted this client. The consent screen warns end-users.

# Client form page headings (client_form.html)
admin-client-form-title-new = New client
admin-client-form-title-edit = Edit client
admin-client-form-heading-new = New OAuth2 client
admin-client-form-heading-edit = Edit client
admin-client-form-preset-note = Defaults are pre-filled for this type.
admin-client-form-preset-change = Change type

# Client shared form fields (client_form.html, client_show.html edit form)
admin-client-field-name = Client name
admin-client-field-grant-types = Grant types
admin-client-grant-auth-code-hint = (user-driven login)
admin-client-grant-refresh-hint = (long-lived sessions)
admin-client-grant-client-creds-hint = (service-to-service)
admin-client-field-response-types = Response types
admin-client-field-scope = Scope
admin-client-field-scope-hint = Space-separated OAuth2 scopes.
admin-client-field-redirect-uris = Redirect URIs
admin-client-field-redirect-uris-hint = One per line (or comma-separated).
admin-client-field-post-logout-uris = Post-logout redirect URIs
admin-client-section-logout-fanout = OIDC logout fan-out
admin-client-section-logout-fanout-desc = When the user ends their session via Forseti, Hydra notifies clients on these URIs so each app can clear its local session. Leave blank to opt this client out of the fan-out.
admin-client-field-backchannel-uri = Back-channel logout URI
admin-client-field-backchannel-uri-hint = Hydra POSTs a signed logout token here (server-to-server). Typically only meaningful for server-rendered web apps and BFFs.
admin-client-field-backchannel-sid-prefix = Require
admin-client-field-backchannel-sid-suffix = claim in back-channel logout token
admin-client-field-backchannel-sid-short = claim
admin-client-field-frontchannel-uri = Front-channel logout URI
admin-client-field-frontchannel-uri-hint = Hydra iframes this URL during logout so each app can clear its session cookies in-browser.
admin-client-field-frontchannel-sid-prefix = Require
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = query parameters on front-channel logout
admin-client-field-frontchannel-sid-short = query parameters
admin-client-field-token-auth = Token endpoint auth method
admin-client-token-auth-post-hint = (secret in POST body)
admin-client-token-auth-basic-hint = (secret in Authorization header)
admin-client-token-auth-none-hint = (public client, PKCE)
admin-client-token-auth-none-short = none (public + PKCE)
admin-client-field-audience = Audience allow-list
admin-client-field-audience-hint-short = One per line. Hydra requires audience values to be pre-registered here.
admin-client-field-require-pkce = Require PKCE (informational)
admin-client-field-skip-consent = Trusted client (skip consent screen)
admin-client-field-webhook-url = Account deletion webhook URL
admin-client-action-cancel = Cancel

# Client show page (client_show.html)
admin-client-action-revoke-verification = Revoke verification
admin-client-action-mark-verified = Mark as verified
admin-client-action-rotate-secret = Rotate secret
admin-client-action-delete = Delete
admin-client-credentials-heading = Credentials: shown once
admin-client-credentials-note = Copy these now. They won't be shown again; reload to dismiss. The client ID and endpoints above are not secret and stay visible.
admin-client-credentials-secret-label = Client secret
admin-client-credentials-rat-label = Registration access token
admin-client-credentials-rat-note = Per RFC 7592: lets the client manage its own registration (read/update/delete) via Hydra's dynamic-client-registration API. It cannot be re-issued, so if in doubt, store it.
admin-client-undoc-scopes-heading = Undocumented scopes
admin-client-section-connection = Connection details
admin-client-connection-intro = Paste these into the OIDC/OAuth client configuration on the app's side.
admin-client-conn-client-id = Client ID
admin-client-conn-issuer = Issuer
admin-client-conn-discovery-url = Discovery URL
admin-client-conn-auth-endpoint = Authorization endpoint
admin-client-conn-token-endpoint = Token endpoint
admin-client-conn-userinfo-endpoint = Userinfo endpoint
admin-client-conn-jwks-uri = JWKS URI
admin-client-conn-end-session-endpoint = End-session endpoint
admin-client-section-config = Configuration
admin-client-config-sid-required = (sid required)
admin-client-config-iss-sid-required = (iss+sid required)
admin-client-not-configured = not configured
admin-client-audience-none = none
admin-client-config-token-auth = Token endpoint auth
admin-client-config-require-pkce = Require PKCE
admin-client-bool-yes = yes
admin-client-bool-no = no
admin-client-config-trusted = Trusted (skip consent)
admin-client-config-created = Created
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = (DCR caller-declared)
admin-client-config-provenance-url = Used at
admin-client-config-provenance-url-note = (first observed on consent)
admin-client-config-webhook = Account deletion webhook
admin-client-section-edit = Edit
admin-client-action-save = Save changes
admin-client-action-back = Back to list

# Client type picker (client_type_picker.html)
admin-client-type-page-title = New client
admin-client-type-heading = New OAuth2 client
admin-client-type-subtitle = Pick the application type. The next page is the same form, with the right defaults already filled in, so you can't accidentally land on a broken combination.
admin-client-type-popular-heading = Popular apps
admin-client-type-action-cancel = Cancel

# DCR tokens list (dcr_tokens_list.html)
admin-dcr-page-title = DCR initial access tokens
admin-dcr-action-issue = Issue token
admin-dcr-token-revealed-heading = Initial access token (shown once)
admin-dcr-col-status = Status
admin-dcr-col-note = Note
admin-dcr-col-created-by = Created by
admin-dcr-col-created = Created
admin-dcr-col-expires = Expires
admin-dcr-col-uses-left = Uses left
admin-dcr-status-active = Active
admin-dcr-status-revoked = Revoked
admin-dcr-status-expired = Expired
admin-dcr-status-exhausted = Exhausted
admin-dcr-empty-prefix = No tokens issued.
admin-dcr-empty-link = Issue one
admin-dcr-empty-suffix = to enable self-registration.
admin-dcr-action-revoke = Revoke

# DCR token new (dcr_token_new.html)
admin-dcr-new-page-title = Issue DCR token
admin-dcr-new-heading = Issue a DCR initial access token
admin-dcr-new-field-note = Note
admin-dcr-new-field-note-placeholder = What is this token for? (e.g. 'Claude Desktop for formshive')
admin-dcr-new-field-note-hint = Optional, for your records only. The client author never sees this.
admin-dcr-new-field-ttl = TTL (hours)
admin-dcr-new-field-ttl-hint = Leave blank for no expiry.
admin-dcr-new-field-max-uses = Max uses
admin-dcr-new-action-cancel = Cancel

# Status page (status.html)
admin-status-page-title = Status
admin-status-heading = System status
admin-status-subtitle = Live health of the IdP components, courier queue, and build versions.
admin-status-issuer-label = Issuer
admin-status-issuer-config-link = View configuration →
admin-status-warning-db-label = Database
admin-status-warning-db-body = sqlite + production-looking deployment. Multi-instance setups will corrupt the database. Switch to Postgres for HA.
admin-status-warning-webhook-label = Webhook fan-out
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } dead-lettered account-deletion webhook row
       *[other] { $count } dead-lettered account-deletion webhook rows
    }
admin-status-dead-webhook-middle = (receivers are not being notified).
admin-status-dead-webhook-open = Open /admin/webhooks
admin-status-dead-webhook-action = to requeue or discard.
admin-status-section-services = Services
admin-status-col-service = Service
admin-status-col-state = State
admin-status-col-detail = Detail
admin-status-state-up = up
admin-status-state-down = down
admin-status-section-courier = Courier queue
admin-status-courier-pending = Pending (queued)
admin-status-courier-failed = Failed (abandoned)
admin-status-courier-last-webhook = Last audit webhook
admin-status-courier-never = never
admin-status-section-audit = Audit
admin-status-audit-write-failures = Audit write failures (since boot)
admin-status-audit-write-failures-note-prefix = Rows are recoverable from the structured
admin-status-audit-write-failures-note-suffix = stderr lines emitted by Forseti at the time of failure.
admin-status-audit-webhook-rejected = Audit webhook rejected (since boot)
admin-status-audit-webhook-rejected-note-prefix = Malformed payloads or unknown actions, likely a Kratos hook/config mismatch. Check the
admin-status-audit-webhook-rejected-note-suffix = warn logs.
admin-status-audit-freshness = Audit webhook freshness anomalies (since boot)
admin-status-audit-freshness-note = Payloads stamped stale or future-dated, usually a slow flow or clock skew. Rows are still recorded and flagged.
admin-status-audit-webhook-accept-list = Audit webhook accept-list entries
admin-status-audit-webhook-last-matched = Audit webhook last-matched entry
admin-status-audit-webhook-last-matched-none = none since boot
admin-status-section-license = License
admin-status-license-oss-prefix = OSS-tier deployment.
admin-status-license-oss-link = Activate a license
admin-status-license-oss-suffix = to unlock premium features.
admin-status-section-build = Build versions
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Database

# Configuration page (configuration.html)
admin-config-page-title = Configuration
admin-config-subtitle = How this identity provider is configured: OIDC endpoints and capabilities, signing keys, and Kratos identity schemas.
admin-config-discovery-warning-label = OIDC discovery
admin-config-discovery-warning-body = Couldn't reach Hydra's discovery document. Endpoints and capabilities are hidden until it's reachable again.
admin-config-section-oidc = OIDC endpoints
admin-config-field-issuer = Issuer
admin-config-field-discovery-url = Discovery URL
admin-config-field-authorization = Authorization
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = End session
admin-config-field-registration = Registration (DCR)
admin-config-field-revocation = Revocation
admin-config-section-capabilities = Capabilities
admin-config-cap-scopes = Scopes
admin-config-cap-grant-types = Grant types
admin-config-cap-response-types = Response types
admin-config-cap-token-auth-methods = Token endpoint auth methods
admin-config-cap-pkce-methods = PKCE methods
admin-config-cap-id-token-signing-algs = ID token signing algs
admin-config-cap-subject-types = Subject types
admin-config-cap-backchannel-logout = Back-channel logout
admin-config-cap-frontchannel-logout = Front-channel logout
admin-config-cap-yes = Yes
admin-config-cap-no = No
admin-config-section-signing-keys = Signing keys (JWKS)
admin-config-signing-keys-unavailable = Unavailable: couldn't fetch Hydra's public keys.
admin-config-signing-keys-empty = Hydra advertised no signing keys.
admin-config-col-key-id = Key ID
admin-config-col-alg = Alg
admin-config-col-type = Type
admin-config-col-use = Use
admin-config-section-schemas = Kratos identity schemas
admin-config-schemas-unavailable = Unavailable: couldn't fetch identity schemas from Kratos.
admin-config-schemas-empty = No identity schemas registered.

# Audit list (audit.html)
admin-audit-page-title = Audit
admin-audit-subtitle = Append-only event log. Records Forseti-side admin actions, OAuth grants, session changes, and Kratos-flow completions delivered via webhook. Retention is operator-configured (`[audit].audit_retention_days`); pruning is a CLI subcommand, not automated.
admin-audit-filter-email = Email contains
admin-audit-filter-action = Action prefix
admin-audit-filter-severity = Severity
admin-audit-filter-since = Since
admin-audit-severity-any = Any
admin-audit-severity-info = Info
admin-audit-severity-warning = Warning
admin-audit-severity-error = Error
admin-audit-severity-critical = Critical
admin-audit-filter-button = Filter
admin-audit-col-target = Target
admin-audit-col-severity = Severity
admin-audit-col-when = When
admin-audit-col-actor = Actor
admin-audit-col-action = Action
admin-audit-col-actions = Actions
admin-audit-empty = No events match the current filters.
admin-audit-badge-critical = critical
admin-audit-badge-error = error
admin-audit-badge-warning = warning
admin-audit-action-view = View
admin-audit-prev = ‹ Prev
admin-audit-next = Next ›

# Audit detail (audit_show.html)
admin-audit-back = ← Back to audit
admin-audit-show-section-event = Event
admin-audit-show-outcome = Outcome
admin-audit-show-success = success
admin-audit-show-failure = failure
admin-audit-show-section-actor = Actor
admin-audit-show-field-kind = Kind
admin-audit-show-field-email = Email
admin-audit-show-none = none
admin-audit-show-field-identity-id = Identity id
admin-audit-show-section-target = Target
admin-audit-show-field-label = Label
admin-audit-show-deleted = (deleted)
admin-audit-show-field-target-id = Target id
admin-audit-show-section-metadata = Metadata
admin-audit-show-section-request-context = Request context
admin-audit-show-field-ip-hash = IP hash
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = Request id
admin-audit-show-field-org-id = Org id

# Webhooks list (webhooks.html)
admin-webhooks-page-title = Webhooks
admin-webhooks-heading = Dead-lettered webhooks
admin-webhooks-subtitle = Account-deletion notifications that exhausted retries (12 attempts or 72 hours, whichever comes first). Click a row for the full payload and last error, or requeue from the summary if you know the receiver is healthy again.
admin-webhooks-empty = No dead-lettered rows. Everything's getting through.
admin-webhooks-col-client = Client
admin-webhooks-col-event = Event
admin-webhooks-col-attempts = Attempts
admin-webhooks-col-age = Age
admin-webhooks-col-actions = Actions
admin-webhooks-deleted = (deleted)
admin-webhooks-action-view = View
admin-webhooks-action-requeue = Requeue

# Webhook detail (webhook_show.html)
admin-webhook-back = ← Back to webhooks
admin-webhook-heading = Dead-lettered webhook
admin-webhook-action-requeue = Requeue
admin-webhook-action-discard = Discard
admin-webhook-section-delivery = Delivery
admin-webhook-field-client = Client
admin-webhook-deleted = (deleted)
admin-webhook-field-state = State
admin-webhook-field-url = URL
admin-webhook-field-attempts = Attempts
admin-webhook-field-created = Created
admin-webhook-field-next-attempt = Next attempt
admin-webhook-section-last-error = Last error
admin-webhook-section-payload = Signed payload

# POSIX accounts list (posix_list.html)
admin-posix-page-title = POSIX accounts
admin-posix-subtitle = Kratos identities materialised into Linux accounts (uid/gid + SSH keys) for the NSS resolver.
admin-posix-seats-label = Seats in use:
admin-posix-license-note = A commercial Linux-authentication license raises the cap.
admin-posix-action-provision = Provision account
admin-posix-col-username = Username
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Status
admin-posix-col-created = Created
admin-posix-empty-prefix = No enabled POSIX accounts.
admin-posix-empty-link = Provision one
admin-posix-empty-suffix = from a Kratos identity.
admin-posix-status-enabled = enabled
admin-posix-status-disabled = disabled
admin-posix-action-manage = Manage

# POSIX account detail (posix_account.html)
admin-posix-action-disable = Disable
admin-posix-action-enable = Enable
admin-posix-action-delete = Delete
admin-posix-ssh-keys-heading = SSH keys
admin-posix-ssh-empty = No SSH keys yet.
admin-posix-ssh-key-added-prefix = added
admin-posix-ssh-action-remove = Remove
admin-posix-ssh-field-public-key = Public key
admin-posix-ssh-field-comment = Comment (optional)
admin-posix-ssh-action-add = Add key
admin-posix-teams-heading = Teams
admin-posix-hosts-heading = Reachable hosts
admin-posix-back = ← All POSIX accounts

# POSIX account new (posix_new.html)
admin-posix-new-page-title = Provision POSIX account
admin-posix-new-heading = Provision a POSIX account
admin-posix-new-choose-identity = Choose the identity to provision.
admin-posix-new-action-select-user = Select user
admin-posix-new-or-enter-directly = Or enter directly
admin-posix-new-placeholder-id = UUID or email
admin-posix-new-action-continue = Continue
admin-posix-new-provision-intro = Materialise a Kratos identity into a Linux account. A uid/gid is allocated automatically and a primary group created.
admin-posix-new-selected-prefix = Selected:
admin-posix-new-action-change = Change
admin-posix-new-field-username = Username
admin-posix-new-username-hint = Suggested from the email; edit if you like. 1–32 chars, lowercase, starting with a letter or underscore. This becomes the POSIX login name.
admin-posix-new-field-shell = Login shell
admin-posix-new-action-cancel = Cancel

# Hosts list (hosts_list.html)
admin-hosts-page-title = Hosts
admin-hosts-subtitle = Linux machines enrolled against Forseti's POSIX/NSS resolver. Each host authenticates with a one-shot secret you reveal on enrollment.
admin-hosts-action-enroll = Enroll host
admin-hosts-credential-heading = Host credential (shown once)
admin-hosts-credential-note-prefix = Format is
admin-hosts-credential-note-suffix = . Configure the host agent with this credential now. We don't store the raw secret, only its SHA-256.
admin-hosts-col-hostname = Hostname
admin-hosts-col-teams = Teams
admin-hosts-col-force-mfa = Force MFA
admin-hosts-col-enrolled = Enrolled
admin-hosts-col-last-seen = Last seen
admin-hosts-empty-prefix = No hosts enrolled.
admin-hosts-empty-link = Enroll one
admin-hosts-empty-suffix = to let it resolve POSIX accounts.
admin-hosts-status-mfa-pending = MFA (pending)
admin-hosts-mfa-pending-title = Recorded but not yet enforced; enforcement lands with interactive login (PAM).
admin-hosts-action-edit = Edit
admin-hosts-action-rotate = Rotate
admin-hosts-action-revoke = Revoke

# Host edit (hosts_edit.html)
admin-hosts-edit-page-title = Edit host
admin-hosts-edit-intro = Update the host label, its MFA flag, and the teams it's scoped to. The secret is not shown here; rotate it from the hosts list if you need a fresh one.
admin-hosts-field-hostname = Hostname
admin-hosts-hostname-hint = A label for your records. Doesn't have to match the machine's actual hostname.
admin-hosts-field-org = Organization
admin-hosts-org-fixed-note = A host's org is fixed at enrollment and can't be changed here.
admin-hosts-field-allowed-teams = Allowed teams
admin-hosts-teams-empty = No teams exist yet. This host allows any org member. Scoping a host to specific teams needs the Organizations feature.
admin-hosts-teams-hint = Restrict this host to members of the selected teams. Select none to allow any org member.
admin-hosts-field-force-mfa = Force MFA on this host
admin-hosts-force-mfa-hint = Recorded now; enforced once interactive login (PAM) ships.
admin-hosts-action-cancel = Cancel

# Host new (hosts_new.html)
admin-hosts-new-heading = Enroll a Linux host
admin-hosts-new-intro-prefix = A one-shot secret is revealed once on the next page. Configure the host agent with the
admin-hosts-new-intro-suffix = credential it shows.
admin-hosts-org-belongs-hint = The host belongs to this org. Fixed after enrollment.
admin-hosts-new-teams-empty = No teams exist yet. This host will allow any org member. Scoping a host to specific teams needs the Organizations feature.
admin-hosts-new-teams-scope-hint = Restrict this host to members of the selected teams. Only teams in the chosen org apply; select none to allow any org member.

# SAML SSO list (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = Enterprise SAML connections, one per organization. IdP metadata and certificates live in Jackson; Forseti keeps the anchor row and the enable switch.
admin-saml-action-new = New connection
admin-saml-grace-notice = License in grace period. SAML connections are read-only until the license is renewed. SSO logins keep working.
admin-saml-col-org = Org
admin-saml-col-connection = Connection
admin-saml-col-sso-url = SSO URL
admin-saml-col-enabled = Enabled
admin-saml-empty-prefix = No SAML connections yet.
admin-saml-empty-link = Create one
admin-saml-empty-suffix = to enable SSO for an organization.
admin-saml-status-enabled = Enabled
admin-saml-status-disabled = Disabled
admin-saml-action-disable = Disable
admin-saml-action-enable = Enable
admin-saml-action-delete = Delete
admin-saml-idp-values-heading = Values for the customer's IdP admin
admin-saml-idp-values-intro = Hand these to whoever configures the SAML app on the identity-provider side. They're the same for every connection.
admin-saml-idp-acs-url = ACS URL
admin-saml-idp-entity-id = SP entity ID

# Audit pagination
admin-audit-range = Showing { $from }–{ $to } of { $total } rows.
admin-audit-page = Page { $page }
admin-saml-entity-id-note-prefix = The entity ID follows Jackson's
admin-saml-entity-id-note-suffix = setting; change it there if you override the default.

# SAML SSO new connection (saml_new.html)
admin-saml-new-page-title = New SAML connection
admin-saml-new-intro = Connect an organization to its identity provider. Paste the IdP's metadata XML, or give a metadata URL Jackson fetches itself: exactly one of the two.
admin-saml-new-field-org = Organization
admin-saml-new-org-hint = One connection per organization.
admin-saml-new-field-name = Connection name
admin-saml-new-name-hint = For your records only; members never see this.
admin-saml-new-field-metadata-url = Metadata URL
admin-saml-new-metadata-url-hint = Leave blank when pasting raw XML below.
admin-saml-new-metadata-url-https-note = Jackson only fetches HTTPS (or localhost) metadata URLs. For plain-HTTP IdP metadata, paste the XML below instead.
admin-saml-new-field-metadata-xml = Metadata XML
admin-saml-new-metadata-xml-hint = Leave blank when using a metadata URL above.
admin-saml-new-action-create = Create connection
admin-saml-new-action-cancel = Cancel

# Inline-code splits (item 8: 2+ code elements per string)

# client_form.html - response-types hint (code: code, token)
admin-client-field-response-types-hint-part1 = Comma-separated, e.g.
admin-client-field-response-types-hint-part2 = (auth code) or
admin-client-field-response-types-hint-part3 = (client credentials).

# client_form.html - audience hint (code: audience=<value>)
admin-client-field-audience-hint-part1 = One per line. Hydra requires audience values to be pre-registered here (it does not yet support RFC 8707). Clients pass
admin-client-field-audience-hint-part2 = on the authorization request.

# client_form.html - PKCE hint (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = Global enforcement lives in
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). This flag is for operator intent.

# client_form.html + client_show.html - webhook hint (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = When a user self-deletes, Forseti POSTs an RFC 8417 Security Event Token (RISC
admin-client-field-webhook-hint-part2 = ) here. Leave blank to opt out. Receivers verify the JWS against Forseti's JWKS at
admin-client-field-webhook-hint-part3 = .

# client_show.html - undocumented scopes desc (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = These scopes are registered on this client but have no entry under
admin-client-undoc-scopes-desc-part2 = in
admin-client-undoc-scopes-desc-part3 = . The consent screen falls back to the raw scope name for them.

# client_show.html - discovery error (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Couldn't reach Hydra's discovery endpoint, so the issuer and endpoints are hidden to avoid showing a wrong value. Fetch them yourself from
admin-client-discovery-error-part2 = .

# client_show.html - edit section intro (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Update the client fields below. Changes are pushed via Hydra's
admin-client-edit-intro-part2 = ; unrelated fields are preserved.

# dcr_tokens_list.html - subtitle (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Bearer tokens that authorize
admin-dcr-subtitle-part2 = . Hand one to an MCP-client author so they can self-register without you doing it manually.

# dcr_tokens_list.html - revealed-token desc (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Share this with the client author. They send it as
admin-dcr-revealed-desc-part2 = when calling
admin-dcr-revealed-desc-part3 = . We don't store the raw value, only its SHA-256.

# dcr_token_new.html - subtitle (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = The token is revealed once on the next page. Hand it to the client author. They send it as
admin-dcr-new-subtitle-part2 = on a single
admin-dcr-new-subtitle-part3 = call.

# dcr_token_new.html - max-uses hint (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Leave blank for unlimited. Single-use (
admin-dcr-new-field-max-uses-hint-part2 = ) is the safest default.

# client_type_picker.html - popular-apps desc (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Pre-filled for a known app. URLs use
admin-client-type-popular-desc-part2 = (and sometimes
admin-client-type-popular-desc-part3 = ) placeholders. Replace them with your app's values after landing on the form.

# posix_account.html - SSH keys paragraph (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Public keys added here are served to the device's sshd (
admin-posix-ssh-keys-desc-part2 = ) so this user can
admin-posix-ssh-keys-desc-part3 = in with their key, no per-host
admin-posix-ssh-keys-desc-part4 = file needed. Requires the host's sshd hook (set up automatically by the
admin-posix-ssh-keys-desc-part5 = Guix service; manual sshd config on other distros). Not used for console / PAM login.

# posix_new.html - shell hint (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Must exist on the device(s) that serve this account;
admin-posix-new-shell-hint-part2 = is the safe cross-distro default (Guix has no
admin-posix-new-shell-hint-part3 = ). Home dir is derived from the home prefix + username.

# saml_list.html - not-configured block (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = isn't configured
admin-saml-not-configured-part2 = add the Jackson bridge settings to
admin-saml-not-configured-part3 = to enable SAML SSO. See
admin-saml-not-configured-part4 = .

# Admin flash messages (shown as banner after a redirect)
flash-identity-disabled = Identity disabled.
flash-identity-enabled = Identity enabled.
flash-session-revoked = Session revoked.
flash-client-create-failed = Failed to create client: { $error }
flash-client-account-deletion-url-rejected = Account-deletion URL rejected: { $error }
flash-client-secret-stage-failed = Client created, but we couldn't stage the secret for one-shot display. Rotate the secret to retrieve a fresh value.
