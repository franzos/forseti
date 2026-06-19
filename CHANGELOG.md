# Changelog

## [Unreleased]

### Added
- App-template logos on the client picker and list — known apps show their logo (grayscale, colour on hover) instead of a letter tile
- 18 more "popular app" client templates: Vaultwarden, Discourse, Apache Superset, WordPress, Penpot, NetBox, Jenkins, Rocket.Chat, Seafile, Actual Budget, Audiobookshelf, Mealie, Matomo, Rancher, OpenProject, Plane, Mattermost, and Atlassian Data Center

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
