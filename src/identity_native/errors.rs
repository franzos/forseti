//! Self-service errors the `/error?id=` page explains, keyed by Kratos's error ids.

use crate::backend::identity::SelfServiceError;

pub(super) const FLOW_EXPIRED: &str = "self_service_flow_expired";
pub(super) const CSRF_VIOLATION: &str = "security_csrf_violation";

/// (id, message, reason) in Kratos's wording.
const ERRORS: &[(&str, &str, &str)] = &[
    (
        FLOW_EXPIRED,
        "self-service flow expired",
        "The self-service flow expired, initialize a new one.",
    ),
    (
        CSRF_VIOLATION,
        "the request was rejected to protect you from Cross-Site-Request-Forgery",
        "Please retry the flow and optionally clear your cookies. The request was rejected to protect you from Cross-Site-Request-Forgery (CSRF) which could cause account takeover, leaking personal information, and other serious security issues.",
    ),
];

pub(super) fn lookup(id: &str) -> Option<SelfServiceError> {
    ERRORS
        .iter()
        .find(|(known, _, _)| *known == id)
        .map(|(id, message, reason)| SelfServiceError {
            id: Some((*id).to_string()),
            message: Some((*message).to_string()),
            reason: Some((*reason).to_string()),
        })
}

/// The `/error` URL for one of the ids above.
pub(super) fn url(id: &str) -> String {
    format!("/error?id={id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_resolve_and_others_do_not() {
        for id in [FLOW_EXPIRED, CSRF_VIOLATION] {
            let e = lookup(id).expect("listed");
            assert_eq!(e.id.as_deref(), Some(id));
            assert!(e.message.is_some_and(|m| !m.is_empty()));
            assert!(e.reason.is_some_and(|r| !r.is_empty()));
        }
        assert_eq!(lookup("00000000-0000-4000-8000-000000000000"), None);
        assert_eq!(url(FLOW_EXPIRED), "/error?id=self_service_flow_expired");
    }
}
