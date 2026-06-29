# Changelog

## [Unreleased]

### Added
- POSIX provisioning: searchable identity picker, accept a UUID or an email
- Edit an enrolled host after enrollment
- Scope a host to any of several org groups, not just one
- "Use a different account" on the OAuth consent screen, to re-authenticate as someone else
- OIDC `groups` claim: a client granted the `groups` scope receives the user's active-org team slugs (flat array) in the ID token and userinfo, for downstream role mapping (e.g. Parseable, Grafana, ArgoCD).

### Changed
- Grouped the admin and settings navigation into labelled sections
- Team slugs are now immutable after creation; renaming a team changes its display name only.

### Fixed
- Login-screen sign-out hit a CSRF 403 on the account-switch path
- "Revoke access" on Authorized apps failed against Hydra v2 (it sent a client id and the revoke-all flag together, which Hydra rejects with a 400)

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
