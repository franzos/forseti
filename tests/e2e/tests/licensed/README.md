# Licensed e2e specs

Specs in this bucket assume the portal has an **active** license row in
`portal.db` (no expiry, or expiry in the future). Activate
`tests/fixtures/license/active.blob` via `/admin/license` before running
`make e2e-licensed`.

Surfaces to cover: org create + member-invite happy paths, license-settings
page in "Active" state, feature-gated admin actions returning the real
handler instead of the upsell.
