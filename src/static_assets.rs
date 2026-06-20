//! `static/` embedded via `include_dir!` so the binary is self-contained.
//! Whole-tree embed (not file-by-file) because logos are referenced
//! dynamically from templates as `/static/logos/{src}`.

use axum::extract::Path;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use include_dir::{include_dir, Dir};
use sha2::{Digest, Sha256};

use crate::state::AppState;

static STATIC_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/static");

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/static/{*path}", get(serve))
}

async fn serve(Path(path): Path<String>, headers: HeaderMap) -> Response {
    let Some(file) = STATIC_DIR.get_file(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = file.contents();

    let etag = format!("\"{}\"", hex::encode(Sha256::digest(bytes)));
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if inm.as_bytes() == etag.as_bytes() {
            return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
        }
    }

    // Fonts are filename-versioned (cache forever); css/js/svg sit at stable URLs, so revalidate via ETag.
    let cache_control = if path.starts_with("fonts/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };

    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_owned()),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, cache_control.to_owned()),
        ],
        bytes.to_vec(),
    )
        .into_response()
}
