# Expired-license e2e specs

Specs in this bucket assume the portal has an **expired** license row in
`portal.db` (past `expires_at`, still inside or past the configured grace
window). Activate `tests/fixtures/license/expired.blob` via `/admin/license`
before running `make e2e-expired`.

Surfaces to cover: grace banner copy, read-only gating on org-admin actions,
upsell page after hard expiry.
