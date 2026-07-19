# Changelog

## [0.1.14] - 2026-07-19

### Added
- OAuth `organization_id` pin accepts an org slug as well as an id
- Non-members are offered a one-time join into a pinned public org during app login
- Sign-in link on the public org landing page

### Changed
- Public org landing note now points to on-page sign-in/register

## [0.1.13] - 2026-07-18

### Added
- `[oauth].login_session_remember_for` to configure Hydra's login SSO session lifetime (defaults to 24h)

### Fixed
- Authorized apps no longer disappear after an hour; a remembered consent grant now persists until revoked

## [0.1.12] - 2026-07-17

### Security
- Secret-holding config values (cookie secret, PAM client secret, metrics scrape token, audit webhook tokens) are redacted in debug output
- Webhook signing key and the SQLite database (plus `-wal`/`-shm`) are created with owner-only (0600) permissions; previously both were briefly or permanently world-readable under the default umask
- Anonymous client registration (`POST /oauth2/register`) now also has a global rate limit, configurable via `[oauth].dcr_global_rate_per_minute` / `dcr_global_rate_per_hour` (defaults 40/400)
- The default audit IP-pseudonymization salt is now derived from the cookie secret instead of the public instance URL, which made de-pseudonymization feasible from a log dump alone. Pseudonymized IPs in existing audit rows won't correlate with new ones, and rotating the cookie secret rotates them again; set `[audit].ip_salt` to opt out (a boot warning reminds you)
- Tailwind CLI downloads in the container build and the release workflow are now pinned by checksum

### Changed
- `/admin/status` probes Kratos and Hydra concurrently, so the page loads quickly even when an upstream is down
- The dead-letter list on `/admin/webhooks` is capped at 500 rows

### Fixed
- A replaced or removed org logo could keep being served from the in-process cache indefinitely
- Anonymous requests (e.g. to a public org logo) no longer trigger a needless Kratos session lookup
- Consent-session pagination no longer stops early on an unexpected Hydra `Link` header part, which could have left some sessions out of the account-deletion webhook fan-out
- PAM module: opaque FFI handle types switched from empty enums to the sound `repr(C)` pattern
- Org branding and theme changes are now recorded in the audit log
- Malformed consent submissions render a friendly error instead of a raw deserialization message

## [0.1.11] - 2026-07-13

### Added
- `forseti config` interactive menu and non-interactive subcommands: enable/disable OIDC sign-in providers, rotate/prune the audit webhook token and Kratos/Hydra secrets, set courier SMTP, restore from backups, `status` view
- Audit webhook token accept-list for zero-loss rotation
- `config check` lints for OIDC providers, mappers, flow hooks, secret lists, and config.toml consistency

### Changed
- CLI parsing moved to clap; unrecognized subcommands now error instead of starting the server
- `config init` templates are comment-free; rationale moved to the operator guide and the CLI's own descriptions

### Fixed
- Container image failed to build since the legal pages landed: the build stage never copied `assets/`, so ghcr was stuck at 0.1.8

## [0.1.10] - 2026-07-10

### Added
- Operator-editable legal pages: `/privacy`, `/terms`, `/imprint`, with per-locale overrides
- Social login and linked-providers page show provider names and brand icons

### Fixed
- Translated UI was broken in the container image: locales weren't bundled

## [0.1.9] - 2026-07-09

### Added
- POSIX provisioning: searchable identity picker, accept a UUID or an email
- Edit an enrolled host after enrollment
- Scope a host to any of several org groups, not just one
- "Use a different account" on the OAuth consent screen, to re-authenticate as someone else
- OIDC `groups` claim: a client granted the `groups` scope receives the user's active-org team slugs (flat array) in the ID token and userinfo, for downstream role mapping (e.g. Parseable, Grafana, ArgoCD).
- Per-organization theming: brand colors and a preset applied to login, consent, and registration
- Three built-in themes (default, midnight, cyberpunk) with auto-derived dark-mode variants
- Public per-org login landing page at `/o/{slug}`, owner-enabled from org branding settings
- Org owners can upload a logo image (PNG/JPEG/WebP, max 256 KB) from the branding page, validated by magic bytes
- The authenticated app is white-labeled by the active organization's theme
- Tenant logos render on login, registration, and the public landing page

### Changed
- Grouped the admin and settings navigation into labelled sections
- Team slugs are now immutable after creation; renaming a team changes its display name only.
- Outbound mail (org invites + claim-email) now goes through polymail: the `[smtp]` config section becomes `[email]` with a `provider` field, adding Lettermint, Postmark, and SendGrid alongside SMTP. Secrets inject via env (`FORSETI_EMAIL__TOKEN` / `__API_KEY` / `__PASS`). SMTP fields renamed (`scheme` to `tls` with `none`/`start_tls`/`implicit`, `username`/`password` to `user`/`pass`, `from` to `from_address`); the `skip_tls_verify` escape hatch is dropped.

### Security
- Safe response headers: X-Content-Type-Options, X-Frame-Options, minimal CSP
- Reserved and lookalike organization-name denylist on create and rename
- Operator trust-anchor on themed pre-auth pages; audit log for public-login and logo changes
- Enforce the configured `[posix].offline_min_len` when minting offline verifiers
- POSIX rate limiters no longer trust `X-Forwarded-For` behind an untrusted proxy

### Fixed
- Login-screen sign-out hit a CSRF 403 on the account-switch path
- "Revoke access" on Authorized apps failed against Hydra v2 (it sent a client id and the revoke-all flag together, which Hydra rejects with a 400)
- Offline-passphrase hashing blocked the async runtime while computing Argon2
- Concurrent POSIX uid/gid allocation could collide; a team's gid could change after being served
- Offline verifier sync silently dropped accounts past 500 per org
- Offline audit uploads acknowledged events that failed to persist

## [0.1.8] - 2026-06-24

### Added
- Linux host authentication (preview): provision Kratos identities into POSIX accounts; enrolled hosts resolve passwd/group/SSH keys
- Interactive Linux login via the OAuth 2.0 Device Authorization Grant (RFC 8628), with `force_mfa` AAL2 enforcement
- Offline Linux login with a dedicated passphrase when the server is unreachable
- `forseti-unix` host client — daemon, NSS module, `pam_forseti.so`, Guix packaging
- Per-host seat cap on provisioned accounts; resolution is never license-gated

### Security
- PAM account stack fails closed on a daemon outage; local/root logins unaffected
- Panic-guarded PAM entrypoints; daemon socket bounded before auth
- Unique device `user_code`; id_token audience pinned to the PAM client; device-auth refuses an empty client secret
- Org member removal now revokes the member from the org's POSIX group
- A `[security].cookie_secret` under 32 bytes now hard-fails boot

### Fixed
- Identity deletion purges POSIX rows at every path; hourly reconcile sweep catches out-of-band deletes
- Expired commercial license re-evaluated hourly, not only at restart
- Org-invite invalid-email redirect used the org id instead of its slug

## [0.1.7] - 2026-06-20

### Added
- Two-factor authentication is enforced at login — once an identity has a second factor, every login (including to connected apps) requires it; driven by Kratos `required_aal: highest_available` on both the session and settings flows
- Recovery codes as the 2FA break-glass — the 2FA page and dashboard warn when you have a second factor but no recovery codes, so losing a device can't lock you out
- `config-check` / `config-init` operator CLI — lint a Kratos/Hydra config against the recommended (security-critical) settings, or generate a fresh pair with CSPRNG-minted secrets
- Sole owners of an organisation with other members can no longer delete their own account — they're asked to transfer ownership first, so an org is never orphaned

### Changed
- Self-host the Geist / JetBrains Mono web fonts instead of loading them from Bunny Fonts — no third-party request, and preloading kills the font-swap flash on page load

### Fixed
- Static assets (provider logos, theme toggle script) 404'd in the Docker image — the runtime stage only copied `styles.css`, not the rest of `static/`
- Dashboard "Active Sessions" tile read 0 with one session signed in — it didn't count the current session, which Kratos's `/sessions` list omits
- Embedded static assets weren't refreshed when files changed — `include_dir!` contents aren't tracked by cargo, so a newly-added asset (e.g. the theme toggle script) 404'd until a clean rebuild; a build script now re-embeds on change
- "Remove security key" buttons on the 2FA page rendered inconsistently — one filled, the rest outlined; they're now uniform

## [0.1.6] - 2026-06-19

### Added
- App-template logos on the client picker and list — known apps show their logo (grayscale, colour on hover) instead of a letter tile
- 18 more "popular app" client templates: Vaultwarden, Discourse, Apache Superset, WordPress, Penpot, NetBox, Jenkins, Rocket.Chat, Seafile, Actual Budget, Audiobookshelf, Mealie, Matomo, Rancher, OpenProject, Plane, Mattermost, and Atlassian Data Center
- `/admin/status` counters for Kratos audit-webhook rejections and freshness anomalies

### Fixed
- Kratos audit webhook no longer aborts self-service flows on slow 2FA enrollment

## [0.1.5] - 2026-06-18

### Added
- Dark / light / system theme, selectable from the top bar (defaults to system, following the browser)

## [0.1.4] - 2026-06-10

### Added
- Enterprise SAML SSO via a Jackson / Ory Polis bridge (commercial)

### Changed
- License grace window fixed at 30 days read-only after expiry

### Docs
- Commercial-feature docs consolidated under `docs/commercial/`

## [0.1.3] - 2026-06-09

### Added
- App templates on the new-client page — a "Popular apps" group pre-fills the form for ~23 known apps (GitLab, Nextcloud, Grafana, …) with their redirect URIs, scope, and auth settings
- Connection-details card on the client detail page showing the issuer, OIDC endpoints, and a labelled client ID to paste into the app
- Labelled one-shot secret reveal after client creation, with a short explainer for the RFC 7592 registration access token

## [0.1.2] - 2026-06-01

### Added
- cargo-deny advisory scan in CI
- Trivy image scan reporting CVEs to the GitHub Security tab

### Changed
- Docker base image: Debian 12 (bookworm) → 13 (trixie)
- CI GitHub Actions updated to latest versions

## [0.1.1] - 2026-05-31

### Changed
- Normalised HTML template formatting (djLint)

## [0.1.0] - 2026-05-30

### Added
- Initial release
