# Changelog

## [Unreleased]

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
