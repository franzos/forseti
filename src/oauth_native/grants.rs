//! Consent grants in `oauth_consent_grants`, keyed by the authorization request id Hydra calls the
//! consent request id, and the authorization codes issued under them.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use diesel::prelude::*;

use super::clients::{self, AUTH_NONE};
use super::{CODE_TTL_SECS, from_json, random_token, token_hash};
use crate::backend::oauth::{ConsentRequest, ConsentSession, OAuthClient};
use crate::db::{DbPool, rfc3339};
use crate::db_interact;
use crate::schema::{oauth_authorization_codes, oauth_consent_grants};

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = oauth_consent_grants)]
pub(super) struct GrantRow {
    pub(super) id: String,
    pub(super) client_id: String,
    pub(super) subject: String,
    pub(super) session_id: String,
    pub(super) scope: String,
    pub(super) audience: String,
    pub(super) id_token_claims: String,
    pub(super) access_token_claims: String,
    pub(super) remember: i32,
    pub(super) skipped: i32,
    pub(super) handled_at: String,
    /// Accepted without a consent screen on the client's `skip_consent`; never a basis for skip.
    pub(super) auto_granted: i32,
    /// When a refresh token of the grant was revoked; once set, none of its access tokens is active.
    pub(super) tokens_revoked_at: Option<String>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = oauth_authorization_codes)]
pub(super) struct NewCode {
    pub(super) code_hash: String,
    pub(super) grant_id: String,
    pub(super) client_id: String,
    pub(super) subject: String,
    pub(super) session_id: String,
    pub(super) redirect_uri: String,
    pub(super) code_challenge: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) scope: String,
    pub(super) audience: String,
    pub(super) auth_time: String,
    pub(super) acr: Option<String>,
    pub(super) amr: String,
    pub(super) family_id: String,
    pub(super) created_at: String,
    pub(super) expires_at: String,
    pub(super) used_at: Option<String>,
}

/// What a code carries besides the grant's scope and audience.
pub(super) struct CodeFor<'a> {
    pub(super) grant: &'a GrantRow,
    pub(super) redirect_uri: &'a str,
    pub(super) code_challenge: Option<&'a str>,
    pub(super) nonce: Option<&'a str>,
    pub(super) auth_time: &'a str,
    pub(super) acr: Option<&'a str>,
    pub(super) amr: &'a str,
}

/// A fresh code and the row that stores its hash.
pub(super) fn new_code(c: &CodeFor<'_>, now: DateTime<Utc>) -> (String, NewCode) {
    let code = random_token();
    let row = NewCode {
        code_hash: token_hash(&code),
        grant_id: c.grant.id.clone(),
        client_id: c.grant.client_id.clone(),
        subject: c.grant.subject.clone(),
        session_id: c.grant.session_id.clone(),
        redirect_uri: c.redirect_uri.to_string(),
        code_challenge: c.code_challenge.map(str::to_string),
        nonce: c.nonce.map(str::to_string),
        scope: c.grant.scope.clone(),
        audience: c.grant.audience.clone(),
        auth_time: c.auth_time.to_string(),
        acr: c.acr.map(str::to_string),
        amr: c.amr.to_string(),
        family_id: uuid::Uuid::new_v4().to_string(),
        created_at: rfc3339(now),
        expires_at: rfc3339(now + chrono::Duration::seconds(CODE_TTL_SECS)),
        used_at: None,
    };
    (code, row)
}

/// RFC 6749 section 10.2: a public client's earlier consent counts only when its redirect URI
/// proves its identity (https, or http on a loopback host), as in Hydra.
fn identity_is_assured(client: &OAuthClient, redirect_uri: &str) -> bool {
    if client.token_endpoint_auth_method.as_deref() != Some(AUTH_NONE) {
        return true;
    }
    url::Url::parse(redirect_uri).is_ok_and(|u| match u.scheme() {
        "https" => true,
        "http" => matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    })
}

/// Whether the newest remembered, unskipped, user-confirmed grant of `subject` to `client` covers
/// the request, so the consent request reports `skip`. `audience` holds the requested `audience` and
/// `resource` values alike; each must be in the grant's audience.
pub(super) async fn consent_skip(
    db: &DbPool,
    subject: &str,
    client: &OAuthClient,
    redirect_uri: &str,
    scope: &[String],
    audience: &[String],
    prompt_consent: bool,
) -> Result<bool> {
    if prompt_consent || !identity_is_assured(client, redirect_uri) {
        return Ok(false);
    }
    let (subject, client_id) = (
        subject.to_string(),
        client.client_id.clone().unwrap_or_default(),
    );
    let newest = db_interact!(db, |c| {
        oauth_consent_grants::table
            .filter(oauth_consent_grants::subject.eq(subject))
            .filter(oauth_consent_grants::client_id.eq(client_id))
            .filter(oauth_consent_grants::remember.eq(1))
            .filter(oauth_consent_grants::skipped.eq(0))
            .filter(oauth_consent_grants::auto_granted.eq(0))
            .order(oauth_consent_grants::handled_at.desc())
            .select((oauth_consent_grants::scope, oauth_consent_grants::audience))
            .first::<(String, String)>(c)
            .optional()
    })?;
    let Some((granted_scope, granted_audience)) = newest else {
        return Ok(false);
    };
    let granted_scope: Vec<String> = from_json(&granted_scope)?;
    let granted_audience: Vec<String> = from_json(&granted_audience)?;
    Ok(scope.iter().all(|s| granted_scope.contains(s))
        && audience.iter().all(|a| granted_audience.contains(a)))
}

/// Remembered, unskipped grants of `subject`, newest first, optionally under one `sid`.
async fn listed(db: &DbPool, subject: &str, sid: Option<&str>) -> Result<Vec<ConsentSession>> {
    let (subject, sid) = (subject.to_string(), sid.map(str::to_string));
    let rows = db_interact!(db, |c| {
        let mut q = oauth_consent_grants::table
            .filter(oauth_consent_grants::subject.eq(subject))
            .filter(oauth_consent_grants::remember.eq(1))
            .filter(oauth_consent_grants::skipped.eq(0))
            .order(oauth_consent_grants::handled_at.desc())
            .select(GrantRow::as_select())
            .into_boxed();
        if let Some(sid) = sid {
            q = q.filter(oauth_consent_grants::session_id.eq(sid));
        }
        q.load::<GrantRow>(c)
    })?;
    let mut clients: HashMap<String, Option<OAuthClient>> = HashMap::new();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if !clients.contains_key(&row.client_id) {
            let client = clients::get(db, &row.client_id).await?;
            clients.insert(row.client_id.clone(), client);
        }
        let client = clients.get(&row.client_id).cloned().flatten();
        out.push(ConsentSession {
            consent_request: Some(ConsentRequest {
                client,
                consent_request_id: Some(row.id.clone()),
                login_session_id: Some(row.session_id),
                skip: Some(false),
                subject: Some(row.subject),
                ..ConsentRequest::default()
            }),
            consent_request_id: Some(row.id),
            grant_access_token_audience: Some(from_json(&row.audience)?),
            grant_scope: Some(from_json(&row.scope)?),
            handled_at: Some(row.handled_at),
            remember: Some(true),
            remember_for: Some(0),
        });
    }
    Ok(out)
}

pub(super) async fn list_by_subject(db: &DbPool, subject: &str) -> Result<Vec<ConsentSession>> {
    listed(db, subject, None).await
}

pub(super) async fn list_by_login_session(
    db: &DbPool,
    subject: &str,
    sid: &str,
) -> Result<Vec<ConsentSession>> {
    listed(db, subject, Some(sid)).await
}

/// Every grant of `subject`, remembered or not; their codes go with them.
pub(super) async fn revoke_for_subject(db: &DbPool, subject: &str) -> Result<()> {
    let subject = subject.to_string();
    db_interact!(db, |c| {
        diesel::delete(
            oauth_consent_grants::table.filter(oauth_consent_grants::subject.eq(subject)),
        )
        .execute(c)
    })?;
    Ok(())
}

pub(super) async fn find(db: &DbPool, id: &str) -> Result<Option<GrantRow>> {
    let id = id.to_string();
    Ok(db_interact!(db, |c| {
        oauth_consent_grants::table
            .find(id)
            .select(GrantRow::as_select())
            .first(c)
            .optional()
    })?)
}

/// An unknown id counts as revoked; its codes and refresh tokens go with it.
pub(super) async fn revoke_by_id(db: &DbPool, id: &str) -> Result<()> {
    let id = id.to_string();
    db_interact!(db, |c| {
        diesel::delete(oauth_consent_grants::table.find(id)).execute(c)
    })?;
    Ok(())
}

pub(super) async fn revoke_for_client(db: &DbPool, subject: &str, client_id: &str) -> Result<()> {
    let (subject, client_id) = (subject.to_string(), client_id.to_string());
    db_interact!(db, |c| {
        diesel::delete(
            oauth_consent_grants::table
                .filter(oauth_consent_grants::subject.eq(subject))
                .filter(oauth_consent_grants::client_id.eq(client_id)),
        )
        .execute(c)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
