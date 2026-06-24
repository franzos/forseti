# Changelog

## [Unreleased]

### Added
- Linux authentication — back your hosts' login accounts off the identity store. Enroll a Linux host at `/admin/hosts` to get a one-time `host_id:secret` (rotate or revoke it later); provision a Kratos identity into a POSIX account at `/admin/posix` (auto-allocated uid/gid + primary group, managed SSH keys, enable/disable/delete); enrolled hosts resolve passwd/group/authorized_keys over an authenticated API on the internal listener. New accounts are gated by a seat cap — free up to `[posix].free_seats`, raised by a commercial Linux-authentication license — but resolving existing accounts is never gated, so a lapsed license can't lock anyone out of their machine. The host-side NSS/sshd client and Guix wiring are forthcoming
- Offline Linux login when the server is unreachable — set a dedicated offline passphrase (≥8 chars, separate from your account password) at `/settings/offline-access`, and an enrolled host can authenticate you at its terminal while partitioned from Forseti. The server stores only an Argon2id verifier and ships it to the hosts you're enabled and scoped on; the host re-peppers it locally. `force_mfa` hosts get an empty set — they always require the network for login, so going offline can't skip your second factor. A deleted, disabled, de-scoped, or passphrase-cleared account drops off the next host sync. Offline-auth attempts on the host are queued and flushed back into the server audit log on reconnect. The host daemon now provisions a `0600` keystore — it re-peppers each verifier with a host-local HMAC key, polls for the current authorized set on an interval (wholesale-replace, so withdrawal is just absence), and gates a local attempt on TTL, max-lifetime, clock-rollback, and a per-user lockout (live-guessing defence only — the Argon2id work factor is the at-rest bound). Honest reduced guarantee: the host pepper lives in a `0600` file, so a stolen host disk or server DB permits an offline brute-force bounded by the Argon2id work factor × passphrase entropy (hence the 8-char floor); TPM sealing of the pepper, which makes the verifier uncheckable off the host, is the planned hardening and not yet shipped. The Guix service provisions the keystore's parent dir (`forseti-unixd`-owned `0700`) and templates the poll interval; a marionette VM test proves the end-to-end flow — a real Argon2id passphrase verifies against a provisioned verifier with the server unreachable, a wrong one is denied, a `force_mfa` host (empty verifier set) is offered no offline credential, and a fully-down daemon fails closed without attempting offline
- Interactive Linux login (`ssh`/console) via the OAuth 2.0 Device Authorization Grant (RFC 8628): an enrolled host starts a device flow for a named account against Forseti, the human approves it in the browser on a host-bound "did *you* just start this login as `<user>` on `<host>`?" screen, and Forseti binds the approving identity to the named POSIX account before the host is told `approved`. `force_mfa` hosts require a fresh AAL2 session with a real second factor (TOTP/WebAuthn/recovery code) — an hours-old or password-only session won't unlock them, and the one-click `verification_uri_complete` is suppressed for those hosts. The host-side `pam_forseti.so` module drives this conversation (shows the device code, polls for approval with a cancel point, bounded well under sshd's `LoginGraceTime`); it's a thin libc-only shim that talks only to the local daemon and fails open (no tty, unknown user, or unreachable daemon all fall through to the next PAM module, never locking anyone out). The Guix wiring is forthcoming

### Security
- Hardened the Linux device-auth path: the host-side `pam_forseti.so` is the sole arbiter of a Forseti user's account stack and now **fails closed** when `forseti-unixd` is unreachable (an NSS-only user can't log in during an outage) while shadow-backed local accounts — including root — still log in normally, so a directory outage never locks you out of your own boxes. The PAM entrypoints are panic-guarded and the daemon socket is bounded before auth (timeout, connection cap, request-frame cap). Server-side, device-auth refuses to run with an unset/empty PAM client secret (no blank Hydra credential), each device flow gets a unique `user_code`, and the id_token audience is pinned exactly to the PAM client
- Removing a member from an organisation (or deleting the org) now revokes them from that org's POSIX group too. Previously only the org-membership row was deleted, so a host scoped to the org's gid kept resolving the ex-member and serving their SSH keys — access that should have been revoked. The identity-delete path was already covered (it purges all POSIX rows)
- A configured `[security].cookie_secret` shorter than 32 bytes now hard-fails boot instead of only warning — a weak HMAC key for signed cookies is always a deployment bug. The unset → ephemeral per-boot key fallback is unchanged

### Fixed
- Deleting an identity now purges its POSIX rows (account, primary group, group memberships, SSH keys) at every delete path — admin delete, self-service account deletion, and the unverified-prune reaper. An orphaned POSIX account would otherwise keep a usable login alive for a deleted identity. An hourly reconcile sweep (also runnable as `posix-reconcile`) catches identities deleted out-of-band via the Kratos admin API
- An expired commercial license stayed fully active until the next restart — the cached status was only recomputed at boot and on activate/deactivate, so a license that booted active never crossed into its grace window or hard-gate. An hourly background task now re-evaluates the expiry against the clock
- Invalid-email errors on org invites redirected to a broken members URL built from the org ID instead of its slug

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
