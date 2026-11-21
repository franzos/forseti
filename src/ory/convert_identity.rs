//! Kratos wire bodies to domain types.

use super::kratos_wire as wire;
use crate::backend::identity::{
    Aal, AuthMethod, Credential, Identity, IdentityState, RecoveryAddress, RecoveryCode, Session,
    SessionDevice, VerifiableAddress,
};

impl From<wire::RecoveryCodeForIdentity> for RecoveryCode {
    fn from(v: wire::RecoveryCodeForIdentity) -> Self {
        RecoveryCode {
            recovery_code: v.recovery_code,
            recovery_link: v.recovery_link,
        }
    }
}

impl From<wire::AuthenticatorAssuranceLevel> for Aal {
    fn from(v: wire::AuthenticatorAssuranceLevel) -> Self {
        match v {
            wire::AuthenticatorAssuranceLevel::Aal0 => Aal::Aal0,
            wire::AuthenticatorAssuranceLevel::Aal1 => Aal::Aal1,
            wire::AuthenticatorAssuranceLevel::Aal2 => Aal::Aal2,
            wire::AuthenticatorAssuranceLevel::Aal3 => Aal::Aal3,
        }
    }
}

impl From<wire::StateEnum> for IdentityState {
    fn from(v: wire::StateEnum) -> Self {
        match v {
            wire::StateEnum::Active => IdentityState::Active,
            wire::StateEnum::Inactive => IdentityState::Inactive,
        }
    }
}

impl From<wire::SessionAuthenticationMethod> for AuthMethod {
    fn from(m: wire::SessionAuthenticationMethod) -> Self {
        AuthMethod {
            aal: m.aal.map(Aal::from),
            completed_at: m.completed_at,
            method: m.method.map(|x| x.as_str().to_string()),
            organization: m.organization,
            provider: m.provider,
            upstream_acr: m.upstream_acr,
            upstream_amr: m.upstream_amr,
        }
    }
}

impl From<wire::SessionDevice> for SessionDevice {
    fn from(d: wire::SessionDevice) -> Self {
        SessionDevice {
            ip_address: d.ip_address,
            user_agent: d.user_agent,
            location: d.location,
        }
    }
}

impl From<wire::Session> for Session {
    fn from(s: wire::Session) -> Self {
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

impl From<wire::VerifiableIdentityAddress> for VerifiableAddress {
    fn from(a: wire::VerifiableIdentityAddress) -> Self {
        VerifiableAddress {
            id: a.id,
            value: a.value,
            via: a.via.as_str().to_string(),
            status: a.status,
            verified: a.verified,
            verified_at: a.verified_at,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

impl From<wire::RecoveryIdentityAddress> for RecoveryAddress {
    fn from(a: wire::RecoveryIdentityAddress) -> Self {
        RecoveryAddress {
            id: a.id,
            value: a.value,
            via: a.via,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

impl From<wire::IdentityCredentials> for Credential {
    fn from(c: wire::IdentityCredentials) -> Self {
        Credential {
            identifiers: c.identifiers,
            config: c.config,
            created_at: c.created_at,
            updated_at: c.updated_at,
            version: c.version,
        }
    }
}

impl From<wire::Identity> for Identity {
    fn from(i: wire::Identity) -> Self {
        Identity {
            id: i.id,
            schema_id: i.schema_id,
            traits: i.traits,
            state: i.state.map(IdentityState::from),
            state_changed_at: i.state_changed_at,
            created_at: i.created_at,
            updated_at: i.updated_at,
            external_id: i.external_id,
            organization_id: i.organization_id,
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
            // Readers fall back to the credential configs.
            sole_sign_in_is_oidc: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enums_map_to_domain_values_with_the_same_wire_names() {
        for s in ["aal0", "aal1", "aal2", "aal3"] {
            let aal = Aal::from(
                serde_json::from_value::<wire::AuthenticatorAssuranceLevel>(json!(s)).unwrap(),
            );
            assert_eq!((json!(aal), aal.to_string()), (json!(s), s.to_string()));
        }
        for s in ["active", "inactive"] {
            let state =
                IdentityState::from(serde_json::from_value::<wire::StateEnum>(json!(s)).unwrap());
            assert_eq!(json!(state), json!(s));
        }
        for s in [
            "password",
            "oidc",
            "totp",
            "lookup_secret",
            "webauthn",
            "code",
            "passkey",
            "profile",
            "saml",
            "deviceauthn",
            "identifier_first",
            "link_recovery",
            "code_recovery",
        ] {
            let m: wire::MethodEnum = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(m.as_str(), s);
        }
        for s in ["email", "sms"] {
            let v: wire::ViaEnum = serde_json::from_value(json!(s)).unwrap();
            assert_eq!(v.as_str(), s);
        }
        assert!(serde_json::from_value::<wire::MethodEnum>(json!("magic_link")).is_err());
        assert!(serde_json::from_value::<wire::ViaEnum>(json!("pigeon")).is_err());
        assert!(
            serde_json::from_value::<wire::AuthenticatorAssuranceLevel>(json!("aal4")).is_err()
        );
        assert!(serde_json::from_value::<wire::StateEnum>(json!("deleted")).is_err());
    }

    #[test]
    fn auth_method_serialises_in_the_export_field_order() {
        let full: wire::SessionAuthenticationMethod = serde_json::from_value(json!({
            "upstream_amr": ["pwd"], "upstream_acr": "acr", "provider": "github",
            "organization": "org", "method": "oidc", "completed_at": "2026-04-01T10:00:00Z",
            "aal": "aal2",
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_string(&AuthMethod::from(full)).unwrap(),
            r#"{"aal":"aal2","completed_at":"2026-04-01T10:00:00Z","method":"oidc","organization":"org","provider":"github","upstream_acr":"acr","upstream_amr":["pwd"]}"#
        );
        let empty: wire::SessionAuthenticationMethod = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            serde_json::to_string(&AuthMethod::from(empty)).unwrap(),
            "{}"
        );
    }

    #[test]
    fn null_metadata_and_organization_flatten_to_none() {
        let i: wire::Identity = serde_json::from_value(json!({
            "id": "id", "schema_id": "default", "schema_url": "", "traits": null,
            "metadata_admin": null, "metadata_public": null, "organization_id": null,
        }))
        .unwrap();
        assert_eq!(i.metadata_admin, Some(None));
        let d = Identity::from(i);
        assert_eq!(
            (
                d.metadata_admin,
                d.metadata_public,
                d.organization_id,
                d.traits
            ),
            (None, None, None, None)
        );
    }
}
