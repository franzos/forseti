//! `POST /admin/clients/{id}/logo` — upload or remove the client's consent-screen logo.

use axum::extract::{Multipart, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::admin::with_org;
use crate::admin::{AdminCtx, render_admin_error};
use crate::audit::{self, AuditCtx, action, target_kind};
use crate::audit_metadata;
use crate::client_logo;
use crate::extractors::forbid_response;
use crate::orgs::AdminScope;
use crate::state::AppState;
use crate::theming::image::{MAX_LOGO_BYTES, validate_logo};

use crate::admin::clients::scope::RequireClientInScope;

/// Parsed multipart body. `_csrf` rides in the body because a multipart
/// POST can't use the form extractor's CSRF wrapper.
struct LogoForm {
    csrf_token: String,
    remove: bool,
    bytes: Option<Vec<u8>>,
}

/// Drains the multipart body, aborting the file field the moment it crosses
/// [`MAX_LOGO_BYTES`] so an oversized upload is never fully buffered — the
/// router's body limit is the outer guard, this is the inner one.
async fn read_form(multipart: &mut Multipart) -> Result<LogoForm, &'static str> {
    let mut form = LogoForm {
        csrf_token: String::new(),
        remove: false,
        bytes: None,
    };
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return Err("malformed multipart body"),
        };
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "_csrf" => form.csrf_token = field.text().await.unwrap_or_default(),
            "remove" => form.remove = field.text().await.unwrap_or_default() == "1",
            "logo" => {
                let mut field = field;
                let mut bytes = Vec::new();
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            bytes.extend_from_slice(&chunk);
                            if bytes.len() > MAX_LOGO_BYTES {
                                return Err("logo file exceeds 256 KB");
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return Err("malformed multipart body"),
                    }
                }
                if !bytes.is_empty() {
                    form.bytes = Some(bytes);
                }
            }
            _ => {}
        }
    }
    Ok(form)
}

pub async fn logo_upload(
    State(state): State<AppState>,
    client_in_scope: RequireClientInScope,
    actx: AuditCtx,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let RequireClientInScope { id, ctx, scope } = client_in_scope;

    let form = match read_form(&mut multipart).await {
        Ok(f) => f,
        Err(msg) => return reject(&state, msg),
    };

    // After the drain, not before: multipart field order isn't guaranteed,
    // so the token may arrive last.
    if !crate::csrf::verify_csrf(&headers, &form.csrf_token) {
        return forbid_response();
    }

    if form.remove {
        return remove_logo(&state, &id, &ctx, &actx, &scope).await;
    }

    let Some(bytes) = form.bytes else {
        return reject(&state, "no logo file provided");
    };
    let content_type = match validate_logo(&bytes) {
        Ok(ct) => ct,
        Err(msg) => return reject(&state, msg),
    };
    let etag = crate::orgs::logo::etag_of(&bytes);
    if let Err(e) = client_logo::upsert(&state.db, &id, bytes, content_type, &etag).await {
        tracing::error!(error = ?e, id, "admin: client logo upsert failed");
        return render_admin_error(
            &state,
            "Upload failed",
            &format!("Could not save the client logo: {e}"),
        );
    }
    invalidate(&state, &id).await;

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_CLIENT_LOGO_UPLOADED, &actx)
            .target(target_kind::OAUTH_CLIENT, id.clone())
            .metadata(audit_metadata!("content_type" => content_type)),
    )
    .await;

    state.flash_redirect(&show_url(&id, &scope), "Client logo updated.")
}

async fn remove_logo(
    state: &AppState,
    id: &str,
    ctx: &AdminCtx,
    actx: &AuditCtx,
    scope: &AdminScope,
) -> Response {
    if let Err(e) = client_logo::delete(&state.db, id).await {
        tracing::error!(error = ?e, id, "admin: client logo delete failed");
        return render_admin_error(
            state,
            "Remove failed",
            &format!("Could not remove the client logo: {e}"),
        );
    }
    invalidate(state, id).await;

    let _ = audit::log(
        &state.db,
        ctx.audit_event(action::ADMIN_CLIENT_LOGO_REMOVED, actx)
            .target(target_kind::OAUTH_CLIENT, id.to_string()),
    )
    .await;

    state.flash_redirect(&show_url(id, scope), "Client logo removed.")
}

async fn invalidate(state: &AppState, id: &str) {
    state
        .logo_cache
        .lock()
        .await
        .remove(&crate::logo_cache::client_key(id));
}

fn show_url(id: &str, scope: &AdminScope) -> String {
    with_org(
        &format!("/admin/clients/{}", ory_client::apis::urlencode(id)),
        scope,
    )
}

fn reject(state: &AppState, msg: &str) -> Response {
    render_admin_error(state, "Logo rejected", msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;

    const BOUNDARY: &str = "XbndY";

    fn part(name: &str, filename: Option<&str>, value: &[u8]) -> Vec<u8> {
        let mut out =
            format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"").into_bytes();
        if let Some(f) = filename {
            out.extend_from_slice(format!("; filename=\"{f}\"").as_bytes());
        }
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
        out
    }

    async fn parse(parts: Vec<Vec<u8>>) -> Result<LogoForm, &'static str> {
        let mut body: Vec<u8> = parts.into_iter().flatten().collect();
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let req = Request::builder()
            .method("POST")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .expect("request builds");
        let mut multipart = Multipart::from_request(req, &())
            .await
            .expect("multipart extracts");
        read_form(&mut multipart).await
    }

    fn png(extra: usize) -> Vec<u8> {
        let mut b = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        b.resize(8 + extra, 0);
        b
    }

    #[tokio::test]
    async fn csrf_field_is_read_even_when_it_arrives_after_the_file() {
        let form = parse(vec![
            part("logo", Some("a.png"), &png(32)),
            part("_csrf", None, b"tok"),
        ])
        .await
        .expect("parses");
        assert_eq!(form.csrf_token, "tok");
        assert_eq!(form.bytes.expect("file present").len(), 40);
        assert!(!form.remove);
    }

    #[tokio::test]
    async fn oversized_file_aborts_mid_stream() {
        let result = parse(vec![part("logo", Some("a.png"), &png(MAX_LOGO_BYTES + 1))]).await;
        assert_eq!(result.err(), Some("logo file exceeds 256 KB"));
    }

    #[tokio::test]
    async fn empty_file_field_is_not_an_upload() {
        let form = parse(vec![
            part("_csrf", None, b"tok"),
            part("logo", Some(""), b""),
            part("remove", None, b"1"),
        ])
        .await
        .expect("parses");
        assert!(form.bytes.is_none());
        assert!(form.remove);
    }

    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        let form = parse(vec![
            part("junk", None, b"whatever"),
            part("_csrf", None, b"tok"),
        ])
        .await
        .expect("parses");
        assert_eq!(form.csrf_token, "tok");
        assert!(form.bytes.is_none());
    }
}
