//! WebAuthn relying party and ceremony state for passkeys (first factor) and security keys (second factor).

use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, SecurityKey, SecurityKeyAuthentication, SecurityKeyRegistration,
    Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use super::NativeBackend;
use super::flows::{Context, FlowRecord, SAVE_ATTEMPTS, Saved};

/// How long an issued challenge stays usable; matches the options' `timeout`.
pub(super) const CEREMONY_LIFETIME: Duration = Duration::from_secs(300);

/// Stored name of every passkey; neither sign-up nor settings asks for one.
pub(super) const PASSKEY_NAME: &str = "Passkey";

/// The flow-context field a ceremony is kept in; a settings flow holds one of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Slot {
    Passkey,
    Key,
}

impl Slot {
    fn purpose(self) -> &'static str {
        match self {
            Self::Passkey => "flow-passkey-ceremony",
            Self::Key => "flow-key-ceremony",
        }
    }

    fn sealed(self, ctx: &Context) -> Option<&str> {
        match self {
            Self::Passkey => ctx.passkey_ceremony.as_deref(),
            Self::Key => ctx.key_ceremony.as_deref(),
        }
    }

    fn field(self, ctx: &mut Context) -> &mut Option<String> {
        match self {
            Self::Passkey => &mut ctx.passkey_ceremony,
            Self::Key => &mut ctx.key_ceremony,
        }
    }
}

/// What a slot seals: the ceremony, the options its document shows, and when it was minted.
#[derive(Serialize, Deserialize)]
struct Held {
    /// Unix seconds, server clock.
    minted_at: i64,
    options: String,
    ceremony: Ceremony,
}

/// Minted less than [`CEREMONY_LIFETIME`] before `now`; a mint time ahead of `now` is not.
fn is_fresh(minted_at: i64, now: i64) -> bool {
    let lifetime = i64::try_from(CEREMONY_LIFETIME.as_secs()).unwrap_or(i64::MAX);
    (0..lifetime).contains(&now.saturating_sub(minted_at))
}

impl NativeBackend {
    fn seal_held(&self, flow_id: &str, slot: Slot, held: &Held) -> String {
        let plain = serde_json::to_vec(held).expect("ceremony state serialises to JSON");
        self.seal_for_flow(slot.purpose(), flow_id, &plain)
    }

    /// The slot's ceremony if it opens for this flow, fresh or not.
    fn held(&self, rec: &FlowRecord, slot: Slot) -> Option<Held> {
        let plain = self.open_for_flow(slot.purpose(), &rec.row.id, slot.sealed(&rec.ctx)?)?;
        serde_json::from_slice(&plain).ok()
    }

    /// The options of each slot's ceremony, in `slots` order. A slot that is empty or stale gets
    /// one from `mint`, stored with a compare-and-swap save; concurrent renders converge on the
    /// first one stored.
    pub(super) async fn offer(
        &self,
        rec: &mut FlowRecord,
        slots: &[Slot],
        mut mint: impl FnMut(Slot, &FlowRecord) -> Result<(Value, Ceremony)>,
    ) -> Result<Vec<String>> {
        for _ in 0..SAVE_ATTEMPTS {
            let now = chrono::Utc::now().timestamp();
            let mut options = Vec::with_capacity(slots.len());
            let mut minted = false;
            for &slot in slots {
                if let Some(held) = self.held(rec, slot).filter(|h| is_fresh(h.minted_at, now)) {
                    options.push(held.options);
                    continue;
                }
                let (shown, ceremony) = mint(slot, rec)?;
                let held = Held {
                    minted_at: now,
                    options: shown.to_string(),
                    ceremony,
                };
                *slot.field(&mut rec.ctx) = Some(self.seal_held(&rec.row.id, slot, &held));
                options.push(held.options);
                minted = true;
            }
            if !minted || rec.save(&self.db).await? == Saved::Done {
                return Ok(options);
            }
            *rec = self
                .load_flow(&rec.row.id)
                .await?
                .ok_or_else(|| anyhow!("flow {} disappeared", rec.row.id))?;
        }
        Err(anyhow!(
            "WebAuthn ceremony of flow {} could not be stored",
            rec.row.id
        ))
    }

    /// Remove the slot's ceremony from the flow and return it if it was fresh. The flow is saved
    /// as it is, so the ceremony is gone from the store before the caller verifies anything;
    /// `None` when another request saved the flow first, and `rec` is then reloaded.
    pub(super) async fn take(&self, rec: &mut FlowRecord, slot: Slot) -> Result<Option<Ceremony>> {
        let Some(held) = self.held(rec, slot) else {
            return Ok(None);
        };
        *slot.field(&mut rec.ctx) = None;
        if rec.save(&self.db).await? == Saved::Changed {
            *rec = self
                .load_flow(&rec.row.id)
                .await?
                .ok_or_else(|| anyhow!("flow {} disappeared", rec.row.id))?;
            return Ok(None);
        }
        Ok(is_fresh(held.minted_at, chrono::Utc::now().timestamp()).then_some(held.ceremony))
    }
}

/// Discoverable sign-in on the first login step.
pub(super) fn passkey_login(rp: &Webauthn) -> Result<(Value, Ceremony)> {
    let (options, state) = rp.start_discoverable_authentication()?;
    Ok((
        json!({ "publicKey": options.public_key }),
        Ceremony::PasskeyLogin(state),
    ))
}

/// Re-authentication with one of the identity's `passkeys`.
pub(super) fn passkey_refresh(rp: &Webauthn, passkeys: &[Passkey]) -> Result<(Value, Ceremony)> {
    let (options, state) = rp.start_passkey_authentication(passkeys)?;
    Ok((
        json!({ "publicKey": options.public_key }),
        Ceremony::PasskeyRefresh(state),
    ))
}

/// Second factor with one of the identity's security `keys`.
pub(super) fn key_login(rp: &Webauthn, keys: &[SecurityKey]) -> Result<(Value, Ceremony)> {
    let (options, state) = rp.start_securitykey_authentication(keys)?;
    Ok((
        json!({ "publicKey": options.public_key }),
        Ceremony::KeyLogin(state),
    ))
}

/// A new passkey for `user`, refusing the authenticators that hold an `exclude` credential.
pub(super) fn passkey_register(
    rp: &Webauthn,
    user: Uuid,
    name: &str,
    exclude: Vec<CredentialID>,
) -> Result<(Value, Ceremony)> {
    let (options, state) = rp.start_passkey_registration(user, name, name, Some(exclude))?;
    Ok((
        passkey_options(&options),
        Ceremony::PasskeyRegister { user, state },
    ))
}

/// A new security key for `user`, refusing the authenticators that hold an `exclude` credential.
pub(super) fn key_register(
    rp: &Webauthn,
    user: Uuid,
    name: &str,
    exclude: Vec<CredentialID>,
) -> Result<(Value, Ceremony)> {
    let (options, state) =
        rp.start_securitykey_registration(user, name, name, Some(exclude), None, None)?;
    let mut options = serde_json::to_value(&options)?;
    // Chromium refuses `credentialProtectionPolicy: userVerificationRequired` unless `userVerification` is `required`.
    if let Some(extensions) = options["publicKey"]["extensions"].as_object_mut() {
        extensions.remove("credentialProtectionPolicy");
        extensions.remove("enforceCredentialProtectionPolicy");
    }
    Ok((options, Ceremony::KeyRegister(state)))
}

/// The passkey `response` registers for `ceremony`, and the user handle it was minted for. `None`
/// for another kind of ceremony or a response that does not parse or verify.
pub(super) fn register_passkey(
    rp: &Webauthn,
    ceremony: Ceremony,
    response: &str,
) -> Option<(Uuid, Passkey)> {
    let Ceremony::PasskeyRegister { user, state } = ceremony else {
        return None;
    };
    let response = serde_json::from_str::<RegisterPublicKeyCredential>(response).ok()?;
    refused(rp.finish_passkey_registration(&response, &state)).map(|passkey| (user, passkey))
}

/// The security key `response` registers for `ceremony`. `None` for another kind of ceremony or
/// a response that does not parse or verify.
pub(super) fn register_key(
    rp: &Webauthn,
    ceremony: Ceremony,
    response: &str,
) -> Option<SecurityKey> {
    let Ceremony::KeyRegister(state) = ceremony else {
        return None;
    };
    let response = serde_json::from_str::<RegisterPublicKeyCredential>(response).ok()?;
    refused(rp.finish_securitykey_registration(&response, &state))
}

/// Why an assertion was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// Another kind of ceremony, a response that does not parse or verify, or a key that is not, or
    /// no longer, the identity's and of the expected kind.
    Invalid,
    /// The signature counter did not advance: a replay or a cloned authenticator.
    Counter,
}

impl Refusal {
    /// The `auth.login_failed` reason.
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_credentials",
            Self::Counter => "counter",
        }
    }
}

fn assertion(response: &str) -> Result<PublicKeyCredential, Refusal> {
    serde_json::from_str(response).map_err(|_| Refusal::Invalid)
}

fn verified(
    result: Result<AuthenticationResult, WebauthnError>,
) -> Result<AuthenticationResult, Refusal> {
    match result {
        Err(WebauthnError::CredentialPossibleCompromise) => Err(Refusal::Counter),
        result => refused(result).ok_or(Refusal::Invalid),
    }
}

/// The verified result of the security key assertion `response` for `ceremony`.
pub(super) fn verify_key_login(
    rp: &Webauthn,
    ceremony: Ceremony,
    response: &str,
) -> Result<AuthenticationResult, Refusal> {
    let Ceremony::KeyLogin(state) = ceremony else {
        return Err(Refusal::Invalid);
    };
    verified(rp.finish_securitykey_authentication(&assertion(response)?, &state))
}

/// The discoverable passkey assertion `response` and the user handle it names, both unverified.
pub(super) fn identify_passkey(
    rp: &Webauthn,
    response: &str,
) -> Result<(PublicKeyCredential, Uuid), Refusal> {
    let response = assertion(response)?;
    let user = refused(rp.identify_discoverable_authentication(&response))
        .ok_or(Refusal::Invalid)?
        .0;
    Ok((response, user))
}

/// The verified result of the discoverable assertion `response` for `ceremony`, checked against
/// the stored `passkey` its credential id names.
pub(super) fn verify_passkey_login(
    rp: &Webauthn,
    ceremony: Ceremony,
    response: &PublicKeyCredential,
    passkey: &Passkey,
) -> Result<AuthenticationResult, Refusal> {
    let Ceremony::PasskeyLogin(state) = ceremony else {
        return Err(Refusal::Invalid);
    };
    verified(rp.finish_discoverable_authentication_v2(response, state, passkey))
}

/// The verified result of the passkey assertion `response` for the re-authentication `ceremony`.
pub(super) fn verify_passkey_refresh(
    rp: &Webauthn,
    ceremony: Ceremony,
    response: &str,
) -> Result<AuthenticationResult, Refusal> {
    let Ceremony::PasskeyRefresh(state) = ceremony else {
        return Err(Refusal::Invalid);
    };
    verified(rp.finish_passkey_authentication(&assertion(response)?, &state))
}

fn refused<T>(result: Result<T, WebauthnError>) -> Option<T> {
    // WebauthnError's Display texts are fixed and quote nothing from the response.
    result
        .inspect_err(|e| tracing::info!(error = %e, "webauthn: ceremony refused"))
        .ok()
}

/// A ceremony in flight, with the webauthn-rs state its `finish_*` call needs.
#[derive(Serialize, Deserialize)]
pub(super) enum Ceremony {
    PasskeyLogin(DiscoverableAuthentication),
    PasskeyRefresh(PasskeyAuthentication),
    /// `user` becomes the passkey's user handle and, at sign-up, the identity id.
    PasskeyRegister {
        user: Uuid,
        state: PasskeyRegistration,
    },
    KeyLogin(SecurityKeyAuthentication),
    KeyRegister(SecurityKeyRegistration),
}

/// RP ID is the host of `self_url`, the allowed origin is `self_url`. `None` outside a secure
/// context (https, or http on `localhost`) and for an IP host.
pub(super) fn relying_party(self_url: &str, name: &str) -> Option<Webauthn> {
    let origin = Url::parse(self_url).ok()?;
    let host = origin.domain()?;
    let secure = match origin.scheme() {
        "https" => true,
        "http" => host == "localhost",
        _ => false,
    };
    if !secure {
        return None;
    }
    WebauthnBuilder::new(host, &origin)
        .ok()?
        .rp_name(name)
        .build()
        .ok()
}

/// Passkey creation options as `{"publicKey":{…}}`, asking for a discoverable credential.
pub(super) fn passkey_options(options: &CreationChallengeResponse) -> serde_json::Value {
    let mut value = serde_json::to_value(options).expect("creation options serialise to JSON");
    let public_key = &mut value["publicKey"];
    if !public_key["authenticatorSelection"].is_object() {
        public_key["authenticatorSelection"] = serde_json::json!({});
    }
    let selection = &mut public_key["authenticatorSelection"];
    selection["residentKey"] = "required".into();
    selection["requireResidentKey"] = true.into();
    value
}

#[cfg(test)]
mod tests {
    use webauthn_rs::prelude::{
        Passkey, PublicKeyCredential, RegisterPublicKeyCredential, SecurityKey, WebauthnError,
    };

    use super::super::test_authenticator::Authenticator;
    use super::*;

    const ORIGIN: &str = "http://localhost:3000";
    const RP_ID: &str = "localhost";

    fn rp() -> Webauthn {
        relying_party(ORIGIN, "Test").expect("localhost is a secure context")
    }

    fn reload(ceremony: &Ceremony) -> Ceremony {
        serde_json::from_str(&serde_json::to_string(ceremony).unwrap()).unwrap()
    }

    fn stored<T: Serialize + serde::de::DeserializeOwned>(credential: &T) -> T {
        serde_json::from_str(&serde_json::to_string(credential).unwrap()).unwrap()
    }

    #[test]
    fn relying_party_needs_a_secure_context_and_a_domain() {
        for url in [
            "https://id.example.com",
            "https://id.example.com/forseti/",
            "http://localhost:3000",
            "http://LOCALHOST",
        ] {
            let rp = relying_party(url, "Test").unwrap_or_else(|| panic!("{url} accepted"));
            assert_eq!(rp.get_allowed_origins(), [Url::parse(url).unwrap()]);
        }
        for url in [
            "http://id.example.com",
            "http://localhost.example.com",
            "http://127.0.0.1:3000",
            "https://192.0.2.1",
            "https://[2001:db8::1]",
            "ftp://id.example.com",
            "not a url",
        ] {
            assert!(relying_party(url, "Test").is_none(), "{url} refused");
        }
    }

    #[tokio::test]
    async fn backend_derives_the_relying_party_from_self_url() {
        let backend = super::super::NativeBackend::for_test(&crate::db::test_pool().await);
        let rp = backend
            .webauthn
            .as_ref()
            .expect("the fixture's self url is localhost");
        assert_eq!(rp.get_allowed_origins(), [Url::parse(ORIGIN).unwrap()]);
    }

    #[test]
    fn passkey_options_ask_for_a_discoverable_credential() {
        let (options, _) = rp()
            .start_passkey_registration(Uuid::new_v4(), "a@x.test", "a@x.test", None)
            .unwrap();
        let value = passkey_options(&options);
        let selection = &value["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required");
        assert_eq!(selection["requireResidentKey"], true);
        assert_eq!(selection["userVerification"], "required");
        assert_eq!(value["publicKey"]["rp"]["id"], RP_ID);
        assert_eq!(value["publicKey"]["rp"]["name"], "Test");
        assert_eq!(
            value["publicKey"]["timeout"].as_u64(),
            u64::try_from(CEREMONY_LIFETIME.as_millis()).ok()
        );
    }

    fn register_passkey(rp: &Webauthn, authenticator: &mut Authenticator) -> (Uuid, Passkey) {
        let user = Uuid::new_v4();
        let (options, state) = rp
            .start_passkey_registration(user, "a@x.test", "a@x.test", None)
            .unwrap();
        let Ceremony::PasskeyRegister { user, state } =
            reload(&Ceremony::PasskeyRegister { user, state })
        else {
            panic!("variant survives the round trip");
        };
        let response = authenticator.register(RP_ID, ORIGIN, &passkey_options(&options));
        let response: RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
        let passkey = rp.finish_passkey_registration(&response, &state).unwrap();
        (user, stored(&passkey))
    }

    #[test]
    fn passkey_registers_and_signs_in_without_an_identifier() {
        let rp = rp();
        let mut authenticator = Authenticator::passkey();
        let (user, mut passkey) = register_passkey(&rp, &mut authenticator);
        assert_eq!(
            authenticator.user_handle.as_deref(),
            Some(&user.as_bytes()[..])
        );

        let (options, state) = rp.start_discoverable_authentication().unwrap();
        let Ceremony::PasskeyLogin(state) = reload(&Ceremony::PasskeyLogin(state)) else {
            panic!("variant survives the round trip");
        };
        let response =
            authenticator.assert(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
        let (handle, credential_id) = rp.identify_discoverable_authentication(&response).unwrap();
        assert_eq!(handle, user);
        assert_eq!(credential_id, passkey.cred_id().as_slice());

        let result = rp
            .finish_discoverable_authentication_v2(&response, state, &passkey)
            .unwrap();
        assert!(result.user_verified());
        assert_eq!(result.counter(), 0);
        assert_eq!(passkey.update_credential(&result), Some(false));
    }

    #[test]
    fn passkey_reauthenticates_against_the_identitys_keys() {
        let rp = rp();
        let mut authenticator = Authenticator::passkey();
        let (_, passkey) = register_passkey(&rp, &mut authenticator);

        let (options, state) = rp
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let Ceremony::PasskeyRefresh(state) = reload(&Ceremony::PasskeyRefresh(state)) else {
            panic!("variant survives the round trip");
        };
        let response =
            authenticator.assert(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
        let result = rp.finish_passkey_authentication(&response, &state).unwrap();
        assert_eq!(result.cred_id(), passkey.cred_id());
    }

    #[test]
    fn passkey_without_user_verification_is_refused() {
        let rp = rp();
        let mut authenticator = Authenticator::passkey();
        authenticator.user_verified = false;
        let (options, state) = rp
            .start_passkey_registration(Uuid::new_v4(), "a@x.test", "a@x.test", None)
            .unwrap();
        let response = authenticator.register(RP_ID, ORIGIN, &passkey_options(&options));
        let response: RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
        assert!(matches!(
            rp.finish_passkey_registration(&response, &state),
            Err(WebauthnError::UserNotVerified)
        ));
    }

    #[test]
    fn security_key_registers_and_asserts_with_an_advancing_counter() {
        let rp = rp();
        let mut authenticator = Authenticator::security_key();
        let (options, state) = rp
            .start_securitykey_registration(
                Uuid::new_v4(),
                "a@x.test",
                "a@x.test",
                None,
                None,
                None,
            )
            .unwrap();
        let Ceremony::KeyRegister(state) = reload(&Ceremony::KeyRegister(state)) else {
            panic!("variant survives the round trip");
        };
        let response =
            authenticator.register(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
        assert!(authenticator.user_handle.is_none());
        let response: RegisterPublicKeyCredential = serde_json::from_value(response).unwrap();
        let mut key: SecurityKey = stored(
            &rp.finish_securitykey_registration(&response, &state)
                .unwrap(),
        );

        let assert_with = |key: &SecurityKey, authenticator: &mut Authenticator| {
            let (options, state) = rp
                .start_securitykey_authentication(std::slice::from_ref(key))
                .unwrap();
            let Ceremony::KeyLogin(state) = reload(&Ceremony::KeyLogin(state)) else {
                panic!("variant survives the round trip");
            };
            let response =
                authenticator.assert(RP_ID, ORIGIN, &serde_json::to_value(&options).unwrap());
            let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
            assert_eq!(response.get_user_unique_id(), None);
            rp.finish_securitykey_authentication(&response, &state)
        };

        authenticator.sign_count = 1;
        let result = assert_with(&key, &mut authenticator).unwrap();
        assert!(!result.user_verified());
        assert_eq!(result.counter(), 1);
        assert_eq!(key.update_credential(&result), Some(true));
        let mut key = stored(&key);

        assert!(matches!(
            assert_with(&key, &mut authenticator),
            Err(WebauthnError::CredentialPossibleCompromise)
        ));
        authenticator.sign_count = 2;
        let result = assert_with(&key, &mut authenticator).unwrap();
        assert_eq!(key.update_credential(&result), Some(true));
    }

    #[test]
    fn a_response_for_another_rp_id_or_origin_is_refused() {
        let rp = rp();
        let mut authenticator = Authenticator::passkey();
        let (_, passkey) = register_passkey(&rp, &mut authenticator);
        for (rp_id, origin, expected) in [
            ("evil.test", ORIGIN, "InvalidRPIDHash"),
            (RP_ID, "http://localhost:4000", "InvalidRPOrigin"),
        ] {
            let (options, state) = rp.start_discoverable_authentication().unwrap();
            let response =
                authenticator.assert(rp_id, origin, &serde_json::to_value(&options).unwrap());
            let response: PublicKeyCredential = serde_json::from_value(response).unwrap();
            let err = rp
                .finish_discoverable_authentication_v2(&response, state, &passkey)
                .unwrap_err();
            assert_eq!(format!("{err:?}"), expected);
        }
    }

    mod ceremonies {
        use std::sync::Arc;

        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use serde_json::Value;

        use super::super::super::flows::{FlowRecord, InitParams, Saved};
        use super::super::super::store::keys::KeyRow;
        use super::super::super::test_authenticator::Authenticator;
        use super::super::super::test_support::{
            Browser, DEVICE, identity_with_password, start, submit,
        };
        use super::super::*;
        use super::{ORIGIN, RP_ID, register_passkey, rp};
        use crate::backend::IdentityBackend;
        use crate::backend::identity::{Aal, FlowFetch, FlowKind};
        use crate::flow_view::Flow;

        async fn setup() -> Arc<NativeBackend> {
            NativeBackend::for_test(&crate::db::test_pool().await)
        }

        async fn signed_in(backend: &NativeBackend, identity: &str, aal: Aal) -> Browser {
            let issued = backend
                .issue_session(identity, "password", None, aal, DEVICE)
                .await
                .unwrap();
            Browser {
                csrf: uuid::Uuid::new_v4().to_string(),
                session: Some(issued.token),
            }
        }

        async fn render(
            backend: &NativeBackend,
            browser: &Browser,
            kind: FlowKind,
            id: &str,
        ) -> Flow {
            match backend.get_flow(kind, id, &browser.cookie()).await.unwrap() {
                FlowFetch::Ok(flow) => *flow,
                _ => panic!("flow {id} is not readable"),
            }
        }

        fn value(flow: &Flow, name: &str) -> Option<String> {
            flow.inputs
                .iter()
                .find(|(_, i)| i.name == name)
                .map(|(_, i)| i.value.clone())
        }

        fn options(flow: &Flow, name: &str) -> Value {
            serde_json::from_str(&value(flow, name).unwrap_or_else(|| panic!("{name} shown")))
                .unwrap()
        }

        async fn load(backend: &NativeBackend, id: &str) -> FlowRecord {
            backend.load_flow(id).await.unwrap().unwrap()
        }

        /// Store the slot's ceremony again as minted `age` seconds ago.
        async fn age(backend: &NativeBackend, id: &str, slot: Slot, age: i64) {
            let mut rec = load(backend, id).await;
            let mut held = backend.held(&rec, slot).expect("a ceremony is held");
            held.minted_at = chrono::Utc::now().timestamp() - age;
            *slot.field(&mut rec.ctx) = Some(backend.seal_held(&rec.row.id, slot, &held));
            assert_eq!(rec.save(&backend.db).await.unwrap(), Saved::Done);
        }

        async fn login_flow(backend: &NativeBackend, browser: &Browser) -> String {
            start(backend, browser, FlowKind::Login, InitParams::default()).await
        }

        async fn insert_key(
            backend: &NativeBackend,
            identity: &str,
            kind: &str,
            id: &[u8],
            credential: String,
        ) {
            let now = crate::db::now_rfc3339();
            let row = KeyRow {
                id: uuid::Uuid::new_v4().to_string(),
                identity_id: identity.to_string(),
                kind: kind.to_string(),
                credential_id: URL_SAFE_NO_PAD.encode(id),
                display_name: "key".to_string(),
                credential,
                sign_count: 0,
                version: 0,
                created_at: now.clone(),
                updated_at: now,
            };
            super::super::super::test_support::sql(&backend.db, move |c| {
                use diesel::RunQueryDsl as _;
                diesel::insert_into(crate::schema::identity_webauthn_keys::table)
                    .values(&row)
                    .execute(c)
            })
            .await;
        }

        #[tokio::test]
        async fn a_challenge_is_minted_once_per_render_burst_and_again_when_stale() {
            let backend = setup().await;
            let browser = Browser::new();
            let id = login_flow(&backend, &browser).await;

            let first = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );
            let again = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );
            assert_eq!(first, again);
            assert_eq!(
                load(&backend, &id).await.row.version,
                1,
                "one write mints it"
            );
            let shown: Value = serde_json::from_str(first.as_deref().unwrap()).unwrap();
            assert_eq!(
                shown.as_object().unwrap().keys().collect::<Vec<_>>(),
                ["publicKey"]
            );
            assert_eq!(shown["publicKey"]["rpId"], RP_ID);
            assert!(shown["publicKey"]["challenge"].is_string());

            age(&backend, &id, Slot::Passkey, 290).await;
            let kept = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );
            assert_eq!(kept, first);

            age(&backend, &id, Slot::Passkey, 300).await;
            let fresh = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );
            assert_ne!(fresh, first, "a stale challenge is replaced");
            let rec = load(&backend, &id).await;
            let held = backend.held(&rec, Slot::Passkey).unwrap();
            assert_eq!(Some(held.options), fresh);
        }

        #[tokio::test]
        async fn concurrent_renders_converge_on_one_ceremony() {
            let backend = setup().await;
            let id = login_flow(&backend, &Browser::new()).await;
            let rp = backend.webauthn.clone().unwrap();
            let (mut a, mut b) = (load(&backend, &id).await, load(&backend, &id).await);
            let shown_a = backend
                .offer(&mut a, &[Slot::Passkey], |_, _| passkey_login(&rp))
                .await
                .unwrap();
            let shown_b = backend
                .offer(&mut b, &[Slot::Passkey], |_, _| passkey_login(&rp))
                .await
                .unwrap();
            assert_eq!(shown_a, shown_b);
            let stored = load(&backend, &id).await;
            assert_eq!(stored.row.version, 1);
            assert_eq!(stored.ctx.passkey_ceremony, a.ctx.passkey_ceremony);
        }

        #[tokio::test]
        async fn take_hands_a_ceremony_out_once() {
            let backend = setup().await;
            let browser = Browser::new();
            let id = login_flow(&backend, &browser).await;
            let shown = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );

            let (mut a, mut b) = (load(&backend, &id).await, load(&backend, &id).await);
            assert!(matches!(
                backend.take(&mut a, Slot::Passkey).await.unwrap(),
                Some(Ceremony::PasskeyLogin(_))
            ));
            assert_eq!(
                load(&backend, &id).await.ctx.passkey_ceremony,
                None,
                "gone from the store before verification"
            );
            assert!(
                backend.take(&mut a, Slot::Passkey).await.unwrap().is_none(),
                "repeated"
            );
            assert!(
                backend.take(&mut b, Slot::Passkey).await.unwrap().is_none(),
                "concurrent"
            );
            assert_eq!(
                b.row.version, a.row.version,
                "the loser holds the current flow"
            );
            assert!(
                backend.take(&mut a, Slot::Key).await.unwrap().is_none(),
                "empty slot"
            );

            let next = value(
                &render(&backend, &browser, FlowKind::Login, &id).await,
                "passkey_challenge",
            );
            assert_ne!(next, shown, "the next render mints a new challenge");
        }

        #[tokio::test]
        async fn an_expired_ceremony_is_spent_and_not_returned() {
            let backend = setup().await;
            let browser = Browser::new();
            let id = login_flow(&backend, &browser).await;
            render(&backend, &browser, FlowKind::Login, &id).await;
            age(&backend, &id, Slot::Passkey, 300).await;
            let mut rec = load(&backend, &id).await;
            assert!(
                backend
                    .take(&mut rec, Slot::Passkey)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(load(&backend, &id).await.ctx.passkey_ceremony, None);
        }

        #[tokio::test]
        async fn a_ceremony_sealed_for_one_flow_does_not_open_on_another() {
            let backend = setup().await;
            let browser = Browser::new();
            let (one, other) = (
                login_flow(&backend, &browser).await,
                login_flow(&backend, &browser).await,
            );
            let shown = value(
                &render(&backend, &browser, FlowKind::Login, &one).await,
                "passkey_challenge",
            );

            let sealed = load(&backend, &one).await.ctx.passkey_ceremony;
            let mut rec = load(&backend, &other).await;
            rec.ctx.passkey_ceremony = sealed.clone();
            rec.ctx.key_ceremony = sealed;
            assert_eq!(rec.save(&backend.db).await.unwrap(), Saved::Done);
            let mut rec = load(&backend, &other).await;
            assert!(
                backend
                    .take(&mut rec, Slot::Passkey)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                backend.take(&mut rec, Slot::Key).await.unwrap().is_none(),
                "nor in the other slot"
            );

            let theirs = value(
                &render(&backend, &browser, FlowKind::Login, &other).await,
                "passkey_challenge",
            );
            assert_ne!(theirs, shown, "the other flow mints its own");
        }

        #[tokio::test]
        async fn no_webauthn_node_or_write_without_a_relying_party() {
            let db = crate::db::test_pool().await;
            let mut cfg = crate::config::AppConfig::test_fixture();
            cfg.self_.url = "http://127.0.0.1:3000".into();
            let backend = NativeBackend::new(&cfg, &db, &[0x42; 32]);
            assert!(backend.webauthn.is_none());
            let webauthn_nodes = |flow: &Flow| {
                flow.node_keys
                    .iter()
                    .filter(|(g, _)| g == "webauthn" || g == "passkey")
                    .count()
            };

            let browser = Browser::new();
            let id = login_flow(&backend, &browser).await;
            let flow = render(&backend, &browser, FlowKind::Login, &id).await;
            assert_eq!(webauthn_nodes(&flow), 0);
            assert_eq!(load(&backend, &id).await.row.version, 0, "nothing minted");

            let identity = identity_with_password(&db, "ann@example.com", true).await;
            let browser = signed_in(&backend, &identity, Aal::Aal1).await;
            let id = start(
                &backend,
                &browser,
                FlowKind::Settings,
                InitParams::default(),
            )
            .await;
            let flow = render(&backend, &browser, FlowKind::Settings, &id).await;
            assert_eq!(webauthn_nodes(&flow), 0);
            let rec = load(&backend, &id).await;
            assert_eq!(
                (rec.ctx.passkey_ceremony, rec.ctx.key_ceremony),
                (None, None)
            );
        }

        #[tokio::test]
        async fn settings_offer_both_registrations_excluding_the_identitys_own_keys() {
            use crate::identity_native::store::keys::{KeyKind, plant};
            let backend = setup().await;
            let identity = identity_with_password(&backend.db, "ann@example.com", true).await;
            let passkey_row = plant(&backend.db, &identity, KeyKind::Passkey).await;
            let key_row = plant(&backend.db, &identity, KeyKind::Webauthn).await;
            let browser = signed_in(&backend, &identity, Aal::Aal2).await;
            let id = start(
                &backend,
                &browser,
                FlowKind::Settings,
                InitParams::default(),
            )
            .await;

            let flow = render(&backend, &browser, FlowKind::Settings, &id).await;
            let user = URL_SAFE_NO_PAD.encode(Uuid::parse_str(&identity).unwrap().as_bytes());
            let excluded = |options: &Value| -> Vec<String> {
                options["publicKey"]["excludeCredentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c["id"].as_str().unwrap().to_string())
                    .collect()
            };
            let rows = super::super::super::store::keys::of_identity(&backend.db, &identity)
                .await
                .unwrap();
            let id_of = |row: &str| {
                rows.iter()
                    .find(|r| r.id == row)
                    .unwrap()
                    .credential_id
                    .clone()
            };

            let passkey = options(&flow, "passkey_create_data");
            assert_eq!(passkey["publicKey"]["user"]["id"], user);
            assert_eq!(passkey["publicKey"]["user"]["name"], "ann@example.com");
            assert_eq!(
                passkey["publicKey"]["authenticatorSelection"]["residentKey"],
                "required"
            );
            assert_eq!(excluded(&passkey), [id_of(&passkey_row)]);

            let key = options(&flow, "webauthn_register_trigger");
            assert_eq!(key["publicKey"]["user"]["id"], user);
            assert_eq!(excluded(&key), [id_of(&key_row)]);

            let remove = |name: &str| value(&flow, name);
            assert_eq!(remove("webauthn_remove").as_deref(), Some(key_row.as_str()));
            assert_eq!(
                remove("passkey_remove").as_deref(),
                Some(passkey_row.as_str())
            );
            assert!(flow.has_node("webauthn", "webauthn_script"));

            let rec = load(&backend, &id).await;
            assert!(rec.ctx.passkey_ceremony.is_some() && rec.ctx.key_ceremony.is_some());
            let again = render(&backend, &browser, FlowKind::Settings, &id).await;
            assert_eq!(
                value(&again, "passkey_create_data"),
                value(&flow, "passkey_create_data")
            );
            assert_eq!(
                value(&again, "webauthn_register_trigger"),
                value(&flow, "webauthn_register_trigger")
            );
        }

        #[tokio::test]
        async fn registration_offers_a_passkey_on_step_two_for_the_typed_address() {
            let backend = setup().await;
            let browser = Browser::new();
            let id = start(
                &backend,
                &browser,
                FlowKind::Registration,
                InitParams::default(),
            )
            .await;
            let flow = render(&backend, &browser, FlowKind::Registration, &id).await;
            assert_eq!(value(&flow, "passkey_create_data"), None, "not on step 1");

            let step = |email: &'static str| [("method", "profile"), ("traits.email", email)];
            submit(
                &backend,
                &browser,
                FlowKind::Registration,
                &id,
                &step("ann@example.com"),
            )
            .await;
            let flow = render(&backend, &browser, FlowKind::Registration, &id).await;
            let first = options(&flow, "passkey_create_data");
            assert_eq!(first["publicKey"]["user"]["name"], "ann@example.com");
            assert_eq!(
                first["publicKey"]["authenticatorSelection"]["requireResidentKey"],
                true
            );
            assert!(flow.has_node("passkey", "passkey_register_trigger"));
            let rec = load(&backend, &id).await;
            let Some(Held {
                ceremony: Ceremony::PasskeyRegister { user, .. },
                ..
            }) = backend.held(&rec, Slot::Passkey)
            else {
                panic!("a passkey registration is held");
            };
            assert_eq!(
                first["publicKey"]["user"]["id"],
                URL_SAFE_NO_PAD.encode(user.as_bytes())
            );

            submit(
                &backend,
                &browser,
                FlowKind::Registration,
                &id,
                &[("screen", "previous")],
            )
            .await;
            submit(
                &backend,
                &browser,
                FlowKind::Registration,
                &id,
                &step("bob@example.com"),
            )
            .await;
            let flow = render(&backend, &browser, FlowKind::Registration, &id).await;
            assert_eq!(
                options(&flow, "passkey_create_data")["publicKey"]["user"]["name"],
                "bob@example.com"
            );
        }

        #[tokio::test]
        async fn refresh_and_second_factor_ask_for_the_identitys_own_keys() {
            let backend = setup().await;
            let rp = rp();
            let identity = identity_with_password(&backend.db, "ann@example.com", true).await;
            let mut authenticator = Authenticator::passkey();
            let (_, passkey) = register_passkey(&rp, &mut authenticator);
            insert_key(
                &backend,
                &identity,
                "passkey",
                passkey.cred_id(),
                serde_json::to_string(&passkey).unwrap(),
            )
            .await;

            let mut token = Authenticator::security_key();
            let (creation, state) = rp
                .start_securitykey_registration(Uuid::new_v4(), "a", "a", None, None, None)
                .unwrap();
            let response = token.register(RP_ID, ORIGIN, &serde_json::to_value(&creation).unwrap());
            let key = rp
                .finish_securitykey_registration(&serde_json::from_value(response).unwrap(), &state)
                .unwrap();
            insert_key(
                &backend,
                &identity,
                "webauthn",
                key.cred_id(),
                serde_json::to_string(&key).unwrap(),
            )
            .await;

            let allowed = |options: &Value| -> Vec<String> {
                options["publicKey"]["allowCredentials"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c["id"].as_str().unwrap().to_string())
                    .collect()
            };
            let browser = signed_in(&backend, &identity, Aal::Aal1).await;

            let refresh = InitParams {
                refresh: true,
                ..InitParams::default()
            };
            let id = start(&backend, &browser, FlowKind::Login, refresh).await;
            let flow = render(&backend, &browser, FlowKind::Login, &id).await;
            let shown = options(&flow, "passkey_challenge");
            assert_eq!(allowed(&shown), [URL_SAFE_NO_PAD.encode(passkey.cred_id())]);
            assert!(flow.has_node("passkey", "passkey_login_trigger"));
            assert!(value(&flow, "webauthn_login_trigger").is_none());

            let aal2 = InitParams {
                aal2: true,
                ..InitParams::default()
            };
            let id = start(&backend, &browser, FlowKind::Login, aal2).await;
            let flow = render(&backend, &browser, FlowKind::Login, &id).await;
            let shown = options(&flow, "webauthn_login_trigger");
            assert_eq!(allowed(&shown), [URL_SAFE_NO_PAD.encode(key.cred_id())]);
            assert!(flow.has_node("webauthn", "webauthn_login"));
            assert!(value(&flow, "passkey_challenge").is_none());
            let rec = load(&backend, &id).await;
            assert!(matches!(
                backend.held(&rec, Slot::Key).map(|h| h.ceremony),
                Some(Ceremony::KeyLogin(_))
            ));
        }
    }
}
