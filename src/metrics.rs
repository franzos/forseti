use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

use crate::commercial::license::{Feature, FeatureStatus};
use crate::state::AppState;

const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub fn install_metrics_recorder() -> PrometheusHandle {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_string()), LATENCY_BUCKETS)
        .expect("valid histogram buckets")
        .build_recorder();
    let handle = recorder.handle();
    if metrics::set_global_recorder(recorder).is_err() {
        tracing::warn!("metrics recorder already installed; /metrics may render stale data");
    }
    handle
}

pub fn scrape_allowed(status: FeatureStatus) -> bool {
    matches!(
        status,
        FeatureStatus::Allowed | FeatureStatus::GraceReadOnly
    )
}

pub fn record_bridged_metrics(audit_failures: u64, last_webhook_epoch: u64) {
    metrics::counter!("forseti_audit_write_failures_total").absolute(audit_failures);
    metrics::gauge!("forseti_last_kratos_webhook_timestamp_seconds").set(last_webhook_epoch as f64);
}

/// Constant-time bearer-token comparison against `Authorization: Bearer <expected>`.
pub fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    // Hash both sides before ct_eq: subtle's slice impl short-circuits on unequal lengths, which would leak a length oracle for the expected token.
    use sha2::Digest;
    let presented_hash = sha2::Sha256::digest(token.as_bytes());
    let expected_hash = sha2::Sha256::digest(expected.as_bytes());
    bool::from(subtle::ConstantTimeEq::ct_eq(
        presented_hash.as_slice(),
        expected_hash.as_slice(),
    ))
}

/// `/metrics` on the internal listener. Fails closed: no license, no token, or a
/// mismatched bearer all 404/401 rather than leaking whether the feature exists.
pub async fn metrics_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !scrape_allowed(state.license.feature(Feature::Observability)) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(expected) = state.metrics_scrape_token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !bearer_matches(&headers, expected) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    record_bridged_metrics(
        crate::audit::audit_write_failures_total(),
        crate::audit::last_kratos_webhook_epoch().unwrap_or(0),
    );
    let body = state.metrics_handle.render();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub async fn track_http_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();
    // Bounded allowlist: a raw method string is attacker-controllable and unbounded.
    let method = match *req.method() {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => "OTHER",
    }
    .to_owned();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let labels = [("method", method), ("path", path), ("status", status)];
    metrics::counter!("http_requests_total", &labels).increment(1);
    metrics::histogram!("http_request_duration_seconds", &labels)
        .record(start.elapsed().as_secs_f64());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commercial::license::FeatureStatus;
    use metrics_exporter_prometheus::PrometheusBuilder;

    #[test]
    fn scrape_allowed_matrix() {
        assert!(scrape_allowed(FeatureStatus::Allowed));
        assert!(scrape_allowed(FeatureStatus::GraceReadOnly));
        assert!(!scrape_allowed(FeatureStatus::Locked));
    }

    #[test]
    fn bridged_metrics_render() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            record_bridged_metrics(42, 1_700_000_000);
        });
        let out = handle.render();
        assert!(
            out.contains("forseti_audit_write_failures_total 42"),
            "got:\n{out}"
        );
        assert!(
            out.contains("forseti_last_kratos_webhook_timestamp_seconds 1700000000"),
            "got:\n{out}"
        );
    }

    #[tokio::test]
    async fn http_metrics_recorded() {
        use axum::{routing::get, Router};
        use tower::ServiceExt;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let app = Router::new()
            .route("/ping", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::track_http_metrics));

        metrics::with_local_recorder(&recorder, || {
            futures::executor::block_on(async {
                let _ = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/ping")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            });
        });

        let out = handle.render();
        assert!(out.contains("http_requests_total"), "got:\n{out}");
        assert!(out.contains("path=\"/ping\""), "got:\n{out}");
    }

    #[test]
    fn bearer_matches_matrix() {
        use axum::http::{header, HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(super::bearer_matches(&h, "secret"));
        assert!(!super::bearer_matches(&h, "wrong"));
        assert!(!super::bearer_matches(&HeaderMap::new(), "secret"));
        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic secret"),
        );
        assert!(!super::bearer_matches(&basic, "secret"));
    }
}
