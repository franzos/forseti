//! Unit-test support: identities with a password, TOTP credentials and lookup codes written
//! straight to the store, and a browser that starts and submits flows.

use std::sync::Arc;

use tokio::sync::{OnceCell, Semaphore};

use super::NativeBackend;
use super::flows::{Dispatch, Form, InitOutcome, InitParams, SubmitOutcome, Submitted};
use super::lookup;
use super::password::{self, PasswordConfig};
use super::session::Device;
use super::store;
use super::totp::{self, TotpConfig};
use crate::backend::identity::FlowKind;
use crate::db::DbPool;

/// The password every [`identity_with_password`] identity has.
pub(super) const PASSWORD: &str = "correct horse battery";

/// One Argon2 hash of [`PASSWORD`] per test process.
async fn password_phc() -> &'static str {
    static PHC: OnceCell<String> = OnceCell::const_new();
    PHC.get_or_init(|| async {
        password::hash(&Arc::new(Semaphore::new(1)), PASSWORD.to_string())
            .await
            .expect("hash the test password")
    })
    .await
}

/// An active identity with [`PASSWORD`]; returns its id.
pub(super) async fn identity_with_password(db: &DbPool, email: &str, verified: bool) -> String {
    let identity = store::create(db, email, Some("Ann"), Some("Lee"), verified)
        .await
        .unwrap()
        .expect("address is free");
    plant_password(db, &identity.id).await;
    identity.id
}

pub(super) async fn plant_password(db: &DbPool, identity_id: &str) {
    let config = PasswordConfig {
        hashed_password: password_phc().await.to_string(),
    };
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(db, identity_id, "password", &config)
            .await
            .unwrap()
    );
}

/// A TOTP credential with a fresh secret; returns the secret.
pub(super) async fn plant_totp(backend: &NativeBackend, identity_id: &str) -> Vec<u8> {
    let secret = totp::new_secret().to_vec();
    let config = TotpConfig::new(&backend.keys.seal, identity_id, &secret);
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(&backend.db, identity_id, "totp", &config)
            .await
            .unwrap()
    );
    secret
}

/// Fresh lookup codes, stored as MACs; returns them in display form.
pub(super) async fn plant_lookup_codes(backend: &NativeBackend, identity_id: &str) -> Vec<String> {
    let codes = lookup::generate();
    let config = lookup::config_for(&backend.keys.lookup_mac, identity_id, &codes);
    let config = serde_json::to_string(&config).unwrap();
    assert!(
        store::insert_credential(&backend.db, identity_id, "lookup_secret", &config)
            .await
            .unwrap()
    );
    codes
}

/// The TOTP code for `secret` at `unix` seconds, computed by `totp-lite`.
pub(super) fn totp_code(secret: &[u8], unix: u64) -> String {
    totp_lite::totp_custom::<totp_lite::Sha1>(totp::STEP_SECS, 6, secret, unix)
}

pub(super) const DEVICE: Device<'static> = Device {
    ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
    user_agent: Some("Mozilla/5.0 test"),
};

/// A browser: its CSRF token and, once signed in, its session token.
#[derive(Clone)]
pub(super) struct Browser {
    pub(super) csrf: String,
    pub(super) session: Option<String>,
}

impl Browser {
    pub(super) fn new() -> Self {
        Self {
            csrf: uuid::Uuid::new_v4().to_string(),
            session: None,
        }
    }

    pub(super) fn cookie(&self) -> String {
        match &self.session {
            Some(s) => format!("forseti_csrf={}; forseti_session={s}", self.csrf),
            None => format!("forseti_csrf={}", self.csrf),
        }
    }
}

/// A new flow of `kind` for `browser`.
pub(super) async fn start(
    backend: &NativeBackend,
    browser: &Browser,
    kind: FlowKind,
    params: InitParams<'_>,
) -> String {
    match backend
        .init_flow(kind, params, &browser.csrf, &browser.cookie())
        .await
        .unwrap()
    {
        InitOutcome::Created(id) => id,
        InitOutcome::Redirect(to) => panic!("no flow, redirected to {to}"),
    }
}

/// Submit `fields` to the flow as `browser`, with a valid CSRF field.
pub(super) async fn submit(
    backend: &NativeBackend,
    browser: &Browser,
    kind: FlowKind,
    id: &str,
    fields: &[(&str, &str)],
) -> Submitted {
    let form = Form(
        fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    );
    match backend
        .submit_flow(kind, id, &form, &browser.cookie(), true, DEVICE)
        .await
        .unwrap()
    {
        Dispatch::Done(done) => done,
        other => panic!("submit not handled: {other:?}"),
    }
}

/// The session token a submit sets.
pub(super) fn session_cookie(done: &Submitted) -> Option<String> {
    let SubmitOutcome::Redirect { set_cookies, .. } = &done.outcome else {
        return None;
    };
    set_cookies.iter().find_map(|c| {
        c.strip_prefix("forseti_session=")
            .map(|rest| rest.split(';').next().unwrap().to_string())
    })
}

/// Flow-level and node message ids saved on the flow.
pub(super) async fn messages(backend: &NativeBackend, id: &str) -> (Vec<u64>, Vec<(String, u64)>) {
    let rec = backend.load_flow(id).await.unwrap().unwrap();
    (
        rec.ctx.messages.iter().map(|m| m.id).collect(),
        rec.ctx
            .node_messages
            .iter()
            .map(|n| (n.node.clone(), n.message.id))
            .collect(),
    )
}

/// The audit actions of a submit, in `Debug` form.
pub(super) fn audit_lines(done: &Submitted) -> Vec<String> {
    done.audit.iter().map(|e| format!("{e:?}")).collect()
}

/// Run `f` on the test pool's one sqlite connection.
pub(super) async fn sql<T: Send + 'static>(
    db: &DbPool,
    f: impl FnOnce(&mut diesel::sqlite::SqliteConnection) -> diesel::QueryResult<T> + Send + 'static,
) -> T {
    let DbPool::Sqlite(pool) = db else {
        unreachable!("test_pool is sqlite")
    };
    pool.get()
        .await
        .unwrap()
        .interact(f)
        .await
        .unwrap()
        .unwrap()
}
