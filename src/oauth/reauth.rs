//! RP-driven re-authentication for the Hydra login bridge: OIDC Core's
//! `prompt=login` and `max_age` (3.1.2.1).
//!
//! Hydra hands Forseti the verbatim `/oauth2/auth` URL as `request_url` but
//! does not act on either parameter itself — it stamps `auth_time` at the
//! moment `accept_login_request` is called, so an RP asking for a fresh
//! authentication used to get a "fresh" token without the user touching a
//! credential. The asks are parsed here and enforced by bouncing through
//! Kratos with `refresh=true`.
//!
//! The bounce needs a terminator, or `prompt=login` re-fires on the way back
//! and loops. [`ReauthMark`] is a signed cookie carrying the challenge, the
//! session's `auth_time` as it stood when we bounced, and the moment we
//! bounced. The ask counts as satisfied only once `auth_time` has moved past
//! the recorded value AND lands at or after the bounce — so the credential was
//! proven in response to this redirect, not before it. Replaying an old mark
//! buys nothing, and a mark cannot be transplanted onto another challenge.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ory;
use crate::signed_cookie::SignedCookie;

/// Longer than a Kratos login flow's 10m lifespan, so a user who takes their
/// time on the login screen still lands back inside the mark's window.
const REAUTH_MARK_TTL_SECS: u64 = 900;

/// Ceiling on a parsed `max_age`, in seconds (100 years). Keeps the
/// milliseconds conversion inside `i64` on an RP-controlled value; any window
/// this wide is indistinguishable from no window at all.
const MAX_AGE_CAP_SECS: i64 = 100 * 365 * 24 * 60 * 60;

pub(crate) fn reauth_mark_cookie<'a>(secure: bool) -> SignedCookie<'a> {
    SignedCookie {
        name: "forseti_oauth_reauth",
        salt: b"forseti::oauth-reauth::v1",
        ttl_secs: REAUTH_MARK_TTL_SECS,
        secure,
        path: "/",
    }
}

/// Signed-cookie payload proving we already bounced this exact login
/// challenge, and what the session's `auth_time` was before we did.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ReauthMark {
    /// Hydra login challenge, so a mark minted for one flow can't satisfy
    /// another.
    pub(crate) c: String,
    /// RFC 3339 `auth_time` at bounce time; empty when the session had none.
    pub(crate) t: String,
    /// RFC 3339 moment of the bounce. An authentication older than this
    /// happened before we asked for one and does not satisfy the ask.
    #[serde(default)]
    pub(crate) b: String,
}

/// A decoded [`ReauthMark`] for this challenge.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mark {
    pub(crate) prior_auth_time: Option<DateTime<Utc>>,
    pub(crate) bounced_at: Option<DateTime<Utc>>,
}

/// What the RP asked for, as far as re-authentication goes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ReauthAsk {
    /// `prompt` contains the `login` value.
    pub(crate) prompt_login: bool,
    /// `max_age=<seconds>`. A negative or unparseable value is ignored, per
    /// OIDC Core's "MAY be ignored if not a valid number".
    pub(crate) max_age: Option<i64>,
}

impl ReauthAsk {
    pub(crate) fn is_empty(&self) -> bool {
        !self.prompt_login && self.max_age.is_none()
    }
}

/// Parse `prompt` and `max_age` out of Hydra's `request_url` (the verbatim
/// `/oauth2/auth` URL the RP called).
pub(crate) fn parse_reauth_ask(request_url: &str) -> ReauthAsk {
    let Ok(url) = url::Url::parse(request_url) else {
        return ReauthAsk::default();
    };
    let mut ask = ReauthAsk::default();
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            // `prompt` is a space-delimited set; `login` may sit beside
            // `consent`, `select_account`, ...
            "prompt" => {
                if v.split_whitespace().any(|p| p == "login") {
                    ask.prompt_login = true;
                }
            }
            "max_age" => {
                // Clamped: the window is compared in milliseconds, and an
                // RP-supplied value near `i64::MAX` would overflow the
                // conversion. Anything past the cap already means "don't care".
                if let Ok(n) = v.trim().parse::<i64>()
                    && n >= 0
                {
                    ask.max_age = Some(n.min(MAX_AGE_CAP_SECS));
                }
            }
            _ => {}
        }
    }
    ask
}

/// When the user last proved a credential on this session: the later of the
/// session's `authenticated_at` and the newest `completed_at` across its
/// authentication methods. Kratos updates `authenticated_at` on an AAL2
/// step-up, but taking the max means a step-up counts even if it did not.
pub(crate) fn session_auth_time(session: &ory::Session) -> Option<DateTime<Utc>> {
    let authenticated_at = session.authenticated_at.as_deref().and_then(parse_rfc3339);
    let newest_method = session.authentication_methods.as_ref().and_then(|methods| {
        methods
            .iter()
            .filter_map(|m| m.completed_at.as_deref().and_then(parse_rfc3339))
            .max()
    });
    match (authenticated_at, newest_method) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

pub(crate) fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Outcome of the re-authentication check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReauthDecision {
    /// Accept the login request as-is.
    Proceed,
    /// Bounce through Kratos with `refresh=true` before accepting.
    Reauthenticate,
}

/// True when the session was authenticated in response to our own bounce:
/// `auth_time` moved strictly past what the mark recorded, and landed at or
/// after the bounce itself.
///
/// Both halves matter. Without the first, a static `auth_time` would satisfy
/// the ask forever; without the second, an authentication that happened
/// *before* we asked — a step-up completed in another tab for a different
/// challenge, say — would count, since `auth_time` is a property of the whole
/// Kratos session rather than of this flow.
fn reauthenticated_for_us(mark: Mark, auth_time: DateTime<Utc>) -> bool {
    let moved = mark.prior_auth_time.is_none_or(|p| auth_time > p);
    let after_bounce = mark.bounced_at.is_none_or(|b| auth_time >= b);
    moved && after_bounce
}

/// Decide whether the RP's ask is already satisfied.
///
/// `mark` is the record of our last bounce for this challenge (`None` when we
/// haven't bounced). It is a loop-breaker, not a blanket exemption:
///
/// - `prompt=login` has no window of its own, so a re-authentication made in
///   response to our bounce is what satisfies it.
/// - `max_age` is enforced on its own terms either way. The mark only widens
///   it by the redirect round-trip the user just made, which is the slack
///   inherent in asking them to authenticate and then measuring how long ago
///   they did.
///
/// A session with no readable `auth_time` fails closed: any ask re-authenticates.
pub(crate) fn decide(
    ask: &ReauthAsk,
    auth_time: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    mark: Option<Mark>,
) -> ReauthDecision {
    if ask.is_empty() {
        return ReauthDecision::Proceed;
    }
    let Some(auth_time) = auth_time else {
        return ReauthDecision::Reauthenticate;
    };
    let fresh_for_us = mark.is_some_and(|m| reauthenticated_for_us(m, auth_time));

    if ask.prompt_login && !fresh_for_us {
        return ReauthDecision::Reauthenticate;
    }
    if let Some(max_age) = ask.max_age {
        // Millisecond precision on purpose: `max_age=0` means "reauthenticate
        // now" (OIDC Core 3.1.2.1), and whole-second truncation would let a
        // session authenticated 200ms ago satisfy it. `saturating_mul` because
        // `max_age` is RP-supplied.
        let elapsed_ms = now.signed_duration_since(auth_time).num_milliseconds();
        if elapsed_ms > max_age.saturating_mul(1000) && !fresh_for_us {
            return ReauthDecision::Reauthenticate;
        }
    }
    ReauthDecision::Proceed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        parse_rfc3339(s).expect("test timestamp parses")
    }

    /// A mark recording `prior` as the session's auth_time, bounced at `at`.
    fn mark(prior: &str, at: &str) -> Mark {
        Mark {
            prior_auth_time: Some(t(prior)),
            bounced_at: Some(t(at)),
        }
    }

    #[test]
    fn no_params_is_an_empty_ask() {
        let ask = parse_reauth_ask("https://hydra.example.com/oauth2/auth?client_id=x");
        assert!(ask.is_empty());
    }

    #[test]
    fn prompt_login_is_parsed_among_other_values() {
        let ask = parse_reauth_ask("https://h/oauth2/auth?prompt=consent%20login&client_id=x");
        assert!(ask.prompt_login);
    }

    #[test]
    fn prompt_consent_alone_is_not_a_login_ask() {
        let ask = parse_reauth_ask("https://h/oauth2/auth?prompt=consent");
        assert!(!ask.prompt_login);
        assert!(ask.is_empty());
    }

    #[test]
    fn prompt_none_is_not_a_login_ask() {
        let ask = parse_reauth_ask("https://h/oauth2/auth?prompt=none");
        assert!(!ask.prompt_login);
    }

    #[test]
    fn max_age_is_parsed_and_malformed_is_ignored() {
        assert_eq!(
            parse_reauth_ask("https://h/oauth2/auth?max_age=300").max_age,
            Some(300)
        );
        assert_eq!(
            parse_reauth_ask("https://h/oauth2/auth?max_age=0").max_age,
            Some(0)
        );
        assert_eq!(
            parse_reauth_ask("https://h/oauth2/auth?max_age=abc").max_age,
            None
        );
        assert_eq!(
            parse_reauth_ask("https://h/oauth2/auth?max_age=-5").max_age,
            None
        );
    }

    #[test]
    fn unparseable_request_url_yields_an_empty_ask() {
        assert!(parse_reauth_ask("not a url").is_empty());
        assert!(parse_reauth_ask("").is_empty());
    }

    #[test]
    fn empty_ask_always_proceeds() {
        let d = decide(
            &ReauthAsk::default(),
            Some(t("2020-01-01T00:00:00Z")),
            t("2026-01-01T00:00:00Z"),
            None,
        );
        assert_eq!(d, ReauthDecision::Proceed);
    }

    #[test]
    fn prompt_login_bounces_a_live_session() {
        let ask = ReauthAsk {
            prompt_login: true,
            max_age: None,
        };
        let now = t("2026-01-01T12:00:00Z");
        // Authenticated one second ago — still has to re-authenticate.
        let d = decide(&ask, Some(t("2026-01-01T11:59:59Z")), now, None);
        assert_eq!(d, ReauthDecision::Reauthenticate);
    }

    #[test]
    fn prompt_login_is_satisfied_once_auth_time_moves_past_the_mark() {
        let ask = ReauthAsk {
            prompt_login: true,
            max_age: None,
        };
        let now = t("2026-01-01T12:00:00Z");
        let after = t("2026-01-01T11:59:00Z");
        assert_eq!(
            decide(
                &ask,
                Some(after),
                now,
                Some(mark("2026-01-01T11:00:00Z", "2026-01-01T11:58:00Z"))
            ),
            ReauthDecision::Proceed
        );
    }

    #[test]
    fn a_replayed_mark_does_not_satisfy_prompt_login() {
        let ask = ReauthAsk {
            prompt_login: true,
            max_age: None,
        };
        let now = t("2026-01-01T12:00:00Z");
        let auth = t("2026-01-01T11:00:00Z");
        // The mark records the same auth_time the session still carries: the
        // user came back without authenticating.
        assert_eq!(
            decide(
                &ask,
                Some(auth),
                now,
                Some(mark("2026-01-01T11:00:00Z", "2026-01-01T11:30:00Z"))
            ),
            ReauthDecision::Reauthenticate
        );
    }

    #[test]
    fn max_age_bounces_a_stale_session_and_accepts_a_fresh_one() {
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(300),
        };
        let now = t("2026-01-01T12:00:00Z");
        assert_eq!(
            decide(&ask, Some(t("2026-01-01T11:50:00Z")), now, None),
            ReauthDecision::Reauthenticate,
            "600s old against max_age=300"
        );
        assert_eq!(
            decide(&ask, Some(t("2026-01-01T11:58:00Z")), now, None),
            ReauthDecision::Proceed,
            "120s old against max_age=300"
        );
    }

    #[test]
    fn max_age_boundary_is_inclusive() {
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(300),
        };
        let now = t("2026-01-01T12:00:00Z");
        assert_eq!(
            decide(&ask, Some(t("2026-01-01T11:55:00Z")), now, None),
            ReauthDecision::Proceed,
            "exactly max_age old is still within the window"
        );
    }

    #[test]
    fn max_age_zero_bounces_a_session_authenticated_this_second() {
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(0),
        };
        let now = t("2026-01-01T12:00:00.400Z");
        assert_eq!(
            decide(&ask, Some(t("2026-01-01T12:00:00.200Z")), now, None),
            ReauthDecision::Reauthenticate,
            "200ms is still older than a zero-second window"
        );
    }

    #[test]
    fn max_age_zero_terminates_via_the_mark() {
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(0),
        };
        let now = t("2026-01-01T12:00:00Z");
        assert_eq!(
            decide(&ask, Some(t("2026-01-01T11:00:00Z")), now, None),
            ReauthDecision::Reauthenticate
        );
        // After the bounce the session is newer than the mark and newer than
        // the bounce itself, so max_age=0 doesn't loop.
        assert_eq!(
            decide(
                &ask,
                Some(t("2026-01-01T11:59:59Z")),
                now,
                Some(mark("2026-01-01T11:00:00Z", "2026-01-01T11:59:58Z"))
            ),
            ReauthDecision::Proceed
        );
    }

    #[test]
    fn an_authentication_predating_the_bounce_does_not_satisfy_the_ask() {
        // The cross-tab case: a step-up completed for a DIFFERENT challenge
        // moves the session-wide auth_time, but it happened before we asked
        // this user to authenticate, so it must not count.
        let ask = ReauthAsk {
            prompt_login: true,
            max_age: None,
        };
        let now = t("2026-01-01T12:00:00Z");
        assert_eq!(
            decide(
                &ask,
                // Newer than the recorded prior, but earlier than the bounce.
                Some(t("2026-01-01T11:30:00Z")),
                now,
                Some(mark("2026-01-01T11:00:00Z", "2026-01-01T11:45:00Z"))
            ),
            ReauthDecision::Reauthenticate
        );
    }

    #[test]
    fn a_mark_does_not_excuse_a_stale_max_age() {
        // A mark is a loop-breaker, not a blanket exemption: an authentication
        // that happened long before the bounce still fails the window.
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(60),
        };
        let now = t("2026-01-01T12:00:00Z");
        assert_eq!(
            decide(
                &ask,
                Some(t("2026-01-01T11:30:00Z")),
                now,
                Some(mark("2026-01-01T11:00:00Z", "2026-01-01T11:50:00Z"))
            ),
            ReauthDecision::Reauthenticate,
            "30 minutes old against max_age=60, mark or no mark"
        );
    }

    #[test]
    fn max_age_is_capped_so_the_millisecond_conversion_cannot_overflow() {
        let ask = parse_reauth_ask(&format!("https://h/oauth2/auth?max_age={}", i64::MAX));
        let capped = ask.max_age.expect("a huge max_age still parses");
        assert!(capped <= MAX_AGE_CAP_SECS);
        // The comparison must not overflow or panic.
        assert_eq!(
            decide(
                &ask,
                Some(t("2020-01-01T00:00:00Z")),
                t("2026-01-01T00:00:00Z"),
                None
            ),
            ReauthDecision::Proceed
        );
    }

    #[test]
    fn a_session_without_auth_time_fails_closed() {
        let ask = ReauthAsk {
            prompt_login: false,
            max_age: Some(3600),
        };
        assert_eq!(
            decide(&ask, None, t("2026-01-01T12:00:00Z"), None),
            ReauthDecision::Reauthenticate
        );
    }

    #[test]
    fn auth_time_takes_the_newest_of_session_and_methods() {
        let mut session = ory::Session::new("sess-1".to_string());
        session.authenticated_at = Some("2026-01-01T10:00:00Z".to_string());
        let mut totp = ory::SessionAuthenticationMethod::new();
        totp.completed_at = Some("2026-01-01T11:30:00Z".to_string());
        let mut pwd = ory::SessionAuthenticationMethod::new();
        pwd.completed_at = Some("2026-01-01T10:00:00Z".to_string());
        session.authentication_methods = Some(vec![pwd, totp]);
        assert_eq!(
            session_auth_time(&session),
            Some(t("2026-01-01T11:30:00Z")),
            "a later second-factor completion is the real auth_time"
        );
    }

    #[test]
    fn auth_time_is_none_without_any_timestamp() {
        let session = ory::Session::new("sess-1".to_string());
        assert_eq!(session_auth_time(&session), None);
    }
}
