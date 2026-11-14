//! Kratos SDK model to domain type conversions. Identity write paths keep the
//! SDK models so `Option<Option<_>>` fields survive a round trip; only plain
//! enums map back.

use ory_client::models as sdk;
use ory_client::models::identity::StateEnum;
use ory_client::models::session_authentication_method::MethodEnum;
use ory_client::models::update_identity_body::StateEnum as UpdateStateEnum;
use ory_client::models::verifiable_identity_address::ViaEnum;

use crate::backend::identity::{
    Aal, AuthMethod, CourierStatus, Credential, Identity, IdentityState, RecoveryAddress,
    RecoveryCode, Session, SessionDevice, VerifiableAddress,
};

impl From<IdentityState> for UpdateStateEnum {
    fn from(v: IdentityState) -> Self {
        match v {
            IdentityState::Active => UpdateStateEnum::Active,
            IdentityState::Inactive => UpdateStateEnum::Inactive,
        }
    }
}

impl From<sdk::RecoveryCodeForIdentity> for RecoveryCode {
    fn from(v: sdk::RecoveryCodeForIdentity) -> Self {
        RecoveryCode {
            recovery_code: v.recovery_code,
            recovery_link: v.recovery_link,
        }
    }
}

impl From<CourierStatus> for sdk::CourierMessageStatus {
    fn from(v: CourierStatus) -> Self {
        match v {
            CourierStatus::Queued => sdk::CourierMessageStatus::Queued,
            CourierStatus::Abandoned => sdk::CourierMessageStatus::Abandoned,
        }
    }
}

impl From<sdk::AuthenticatorAssuranceLevel> for Aal {
    fn from(v: sdk::AuthenticatorAssuranceLevel) -> Self {
        match v {
            sdk::AuthenticatorAssuranceLevel::Aal0 => Aal::Aal0,
            sdk::AuthenticatorAssuranceLevel::Aal1 => Aal::Aal1,
            sdk::AuthenticatorAssuranceLevel::Aal2 => Aal::Aal2,
            sdk::AuthenticatorAssuranceLevel::Aal3 => Aal::Aal3,
        }
    }
}

impl From<StateEnum> for IdentityState {
    fn from(v: StateEnum) -> Self {
        match v {
            StateEnum::Active => IdentityState::Active,
            StateEnum::Inactive => IdentityState::Inactive,
        }
    }
}

fn method_name(m: MethodEnum) -> &'static str {
    match m {
        MethodEnum::Password => "password",
        MethodEnum::Oidc => "oidc",
        MethodEnum::Totp => "totp",
        MethodEnum::LookupSecret => "lookup_secret",
        MethodEnum::Webauthn => "webauthn",
        MethodEnum::Code => "code",
        MethodEnum::Passkey => "passkey",
        MethodEnum::Profile => "profile",
        MethodEnum::Saml => "saml",
        MethodEnum::Deviceauthn => "deviceauthn",
        MethodEnum::IdentifierFirst => "identifier_first",
        MethodEnum::LinkRecovery => "link_recovery",
        MethodEnum::CodeRecovery => "code_recovery",
    }
}

fn via_name(v: ViaEnum) -> &'static str {
    match v {
        ViaEnum::Email => "email",
        ViaEnum::Sms => "sms",
    }
}

impl From<sdk::SessionAuthenticationMethod> for AuthMethod {
    fn from(m: sdk::SessionAuthenticationMethod) -> Self {
        AuthMethod {
            aal: m.aal.map(Aal::from),
            completed_at: m.completed_at,
            method: m.method.map(|x| method_name(x).to_string()),
            organization: m.organization,
            provider: m.provider,
            upstream_acr: m.upstream_acr,
            upstream_amr: m.upstream_amr,
        }
    }
}

impl From<sdk::SessionDevice> for SessionDevice {
    fn from(d: sdk::SessionDevice) -> Self {
        SessionDevice {
            ip_address: d.ip_address,
            user_agent: d.user_agent,
            location: d.location,
        }
    }
}

impl From<sdk::Session> for Session {
    fn from(s: sdk::Session) -> Self {
        Session {
            id: s.id,
            active: s.active,
            issued_at: s.issued_at,
            authenticated_at: s.authenticated_at,
            expires_at: s.expires_at,
            authenticator_assurance_level: s.authenticator_assurance_level.map(Aal::from),
            authentication_methods: s
                .authentication_methods
                .map(|v| v.into_iter().map(AuthMethod::from).collect()),
            devices: s
                .devices
                .map(|v| v.into_iter().map(SessionDevice::from).collect()),
            identity: s.identity.map(|i| Box::new(Identity::from(*i))),
        }
    }
}

impl From<sdk::VerifiableIdentityAddress> for VerifiableAddress {
    fn from(a: sdk::VerifiableIdentityAddress) -> Self {
        VerifiableAddress {
            id: a.id,
            value: a.value,
            via: via_name(a.via).to_string(),
            status: a.status,
            verified: a.verified,
            verified_at: a.verified_at,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

impl From<sdk::RecoveryIdentityAddress> for RecoveryAddress {
    fn from(a: sdk::RecoveryIdentityAddress) -> Self {
        RecoveryAddress {
            id: a.id,
            value: a.value,
            via: a.via,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

impl From<sdk::IdentityCredentials> for Credential {
    fn from(c: sdk::IdentityCredentials) -> Self {
        Credential {
            identifiers: c.identifiers,
            config: c.config,
            created_at: c.created_at,
            updated_at: c.updated_at,
            version: c.version,
        }
    }
}

impl From<sdk::Identity> for Identity {
    fn from(i: sdk::Identity) -> Self {
        Identity {
            id: i.id,
            schema_id: i.schema_id,
            traits: i.traits,
            state: i.state.map(IdentityState::from),
            state_changed_at: i.state_changed_at,
            created_at: i.created_at,
            updated_at: i.updated_at,
            external_id: i.external_id,
            organization_id: i.organization_id.flatten(),
            metadata_public: i.metadata_public.flatten(),
            metadata_admin: i.metadata_admin.flatten(),
            verifiable_addresses: i
                .verifiable_addresses
                .map(|v| v.into_iter().map(VerifiableAddress::from).collect()),
            recovery_addresses: i
                .recovery_addresses
                .map(|v| v.into_iter().map(RecoveryAddress::from).collect()),
            credentials: i
                .credentials
                .map(|m| m.into_iter().map(|(k, c)| (k, c.into())).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enum_names_match_the_sdk_wire_strings() {
        for m in [
            MethodEnum::Password,
            MethodEnum::Oidc,
            MethodEnum::Totp,
            MethodEnum::LookupSecret,
            MethodEnum::Webauthn,
            MethodEnum::Code,
            MethodEnum::Passkey,
            MethodEnum::Profile,
            MethodEnum::Saml,
            MethodEnum::Deviceauthn,
            MethodEnum::IdentifierFirst,
            MethodEnum::LinkRecovery,
            MethodEnum::CodeRecovery,
        ] {
            assert_eq!(json!(m), json!(method_name(m)));
        }
        for v in [ViaEnum::Email, ViaEnum::Sms] {
            assert_eq!(json!(v), json!(via_name(v)));
        }
        for a in [
            sdk::AuthenticatorAssuranceLevel::Aal0,
            sdk::AuthenticatorAssuranceLevel::Aal1,
            sdk::AuthenticatorAssuranceLevel::Aal2,
            sdk::AuthenticatorAssuranceLevel::Aal3,
        ] {
            assert_eq!(json!(a), json!(Aal::from(a)));
            assert_eq!(a.to_string(), Aal::from(a).to_string());
        }
        for s in [StateEnum::Active, StateEnum::Inactive] {
            assert_eq!(json!(s), json!(IdentityState::from(s)));
            assert_eq!(
                json!(s),
                json!(UpdateStateEnum::from(IdentityState::from(s)))
            );
        }
        assert_eq!(
            sdk::CourierMessageStatus::from(CourierStatus::Queued),
            sdk::CourierMessageStatus::Queued
        );
        assert_eq!(
            sdk::CourierMessageStatus::from(CourierStatus::Abandoned),
            sdk::CourierMessageStatus::Abandoned
        );
    }

    #[test]
    fn auth_method_serialises_like_the_sdk() {
        let mut full = sdk::SessionAuthenticationMethod::new();
        full.aal = Some(sdk::AuthenticatorAssuranceLevel::Aal2);
        full.completed_at = Some("2026-04-01T10:00:00Z".to_string());
        full.method = Some(MethodEnum::Oidc);
        full.organization = Some("org".to_string());
        full.provider = Some("github".to_string());
        full.upstream_acr = Some("acr".to_string());
        full.upstream_amr = Some(vec!["pwd".to_string()]);
        for m in [full, sdk::SessionAuthenticationMethod::new()] {
            assert_eq!(
                serde_json::to_string(&m).unwrap(),
                serde_json::to_string(&AuthMethod::from(m.clone())).unwrap()
            );
        }
    }

    #[test]
    fn double_options_flatten_to_none() {
        let mut i = sdk::Identity::new("id".into(), "default".into(), String::new(), None);
        i.metadata_admin = Some(None);
        i.metadata_public = Some(None);
        i.organization_id = Some(None);
        let d = Identity::from(i);
        assert_eq!(
            (d.metadata_admin, d.metadata_public, d.organization_id),
            (None, None, None)
        );
    }
}
