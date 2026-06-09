//! `/admin/configuration` — how this OP/IdP is configured.
//!
//! A read-only window onto the moving parts: Hydra's OIDC discovery doc
//! (endpoints + advertised capabilities), the public JWKS signing keys, and
//! the Kratos identity schemas. Every probe is best-effort — one upstream
//! failure renders its section as "unavailable" without aborting the page.

use axum::{extract::State, response::Response};

use crate::admin::{AdminSection, FORSETI_VERSION};
use crate::extractors::RequireAdmin;
use crate::ory::{self, discovery::OidcDiscovery, hydra::JwkSummary};
use crate::page_chrome::PageChrome;
use crate::render::render;
use crate::state::AppState;

#[derive(askama::Template)]
#[template(path = "admin/configuration.html")]
struct ConfigurationTemplate {
    chrome: PageChrome,
    admin_active: AdminSection,
    /// Cached Hydra discovery doc. When `discovery_ok` is false this is the
    /// empty default and the template hides every discovery-derived row.
    disc: OidcDiscovery,
    /// False when the cold discovery fetch failed (no prior cache) — drives
    /// the "couldn't reach Hydra" note.
    discovery_ok: bool,
    /// Convenience: issuer + the well-known discovery path. Empty when the
    /// issuer is unknown.
    discovery_url: String,
    /// Public signing keys from Hydra's `jwks_uri`. Empty + `jwks_ok=false`
    /// when the fetch failed.
    signing_keys: Vec<JwkSummary>,
    jwks_ok: bool,
    /// Kratos identity schema ids. Empty + `schemas_ok=false` on failure.
    identity_schemas: Vec<String>,
    schemas_ok: bool,
    forseti_version: &'static str,
}

pub async fn show(State(state): State<AppState>, admin: RequireAdmin) -> Response {
    let ctx = admin.ctx;

    let (disc, discovery_ok) = state.openid_configuration().await;

    let discovery_url = if disc.issuer.is_empty() {
        String::new()
    } else {
        format!(
            "{}/.well-known/openid-configuration",
            disc.issuer.trim_end_matches('/')
        )
    };

    let (signing_keys, jwks_ok) = match ory::hydra::signing_keys(&state.ory).await {
        Ok(keys) => (keys, true),
        Err(e) => {
            tracing::warn!(error = ?e, "hydra signing-keys fetch failed");
            (Vec::new(), false)
        }
    };

    let (identity_schemas, schemas_ok) = match ory::kratos::list_identity_schemas(&state.ory).await
    {
        Ok(ids) => (ids, true),
        Err(e) => {
            tracing::warn!(error = ?e, "kratos identity-schemas fetch failed");
            (Vec::new(), false)
        }
    };

    tracing::info!(
        action = "admin.configuration.view",
        actor = %ctx.email,
        "admin action"
    );

    render(&ConfigurationTemplate {
        chrome: PageChrome::from_parts(&state, ctx.email, String::new()),
        admin_active: AdminSection::Configuration,
        disc,
        discovery_ok,
        discovery_url,
        signing_keys,
        jwks_ok,
        identity_schemas,
        schemas_ok,
        forseti_version: FORSETI_VERSION,
    })
}
