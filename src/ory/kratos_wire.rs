//! Kratos request and response bodies. Type names, required fields, nullability
//! and the closed string sets follow the Ory API spec (v1.22.66), so a body the
//! spec rejects fails to decode, with the same error text, instead of being half read.

use std::collections::HashMap;

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend::identity::IdentityState;

/// Absent is `None`, `null` is `Some(None)`, so a read-modify-write sends back what it read.
fn double_option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<Value>>, D::Error> {
    Option::<Value>::deserialize(d).map(Some)
}

/// `traits` is required but nullable.
fn required_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Option::<Value>::deserialize(d)
}

// --- Closed string sets ---------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum AuthenticatorAssuranceLevel {
    Aal0,
    Aal1,
    Aal2,
    Aal3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum StateEnum {
    Active,
    Inactive,
}

/// Authentication method of a session step, and credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MethodEnum {
    Password,
    Oidc,
    Totp,
    LookupSecret,
    Webauthn,
    Code,
    Passkey,
    Profile,
    Saml,
    Deviceauthn,
    IdentifierFirst,
    LinkRecovery,
    CodeRecovery,
}

impl MethodEnum {
    pub fn as_str(self) -> &'static str {
        match self {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ViaEnum {
    Email,
    Sms,
}

impl ViaEnum {
    pub fn as_str(self) -> &'static str {
        match self {
            ViaEnum::Email => "email",
            ViaEnum::Sms => "sms",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RegionEnum {
    EuCentral,
    AsiaNortheast,
    UsEast,
    UsWest,
    Eu,
    Asia,
    Us,
    Global,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CourierMessageStatus {
    Queued,
    Sent,
    Processing,
    Abandoned,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CourierMessageType {
    Email,
    Phone,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TemplateTypeEnum {
    RecoveryInvalid,
    RecoveryValid,
    RecoveryCodeInvalid,
    RecoveryCodeValid,
    VerificationInvalid,
    VerificationValid,
    VerificationCodeInvalid,
    VerificationCodeValid,
    Stub,
    LoginCodeValid,
    RegistrationCodeValid,
    VerifiableAddressChanged,
    AuthenticatorKeyAdded,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StatusEnum {
    Failed,
    Success,
}

// --- Responses --------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(super) struct Identity {
    pub created_at: Option<String>,
    pub credentials: Option<HashMap<String, IdentityCredentials>>,
    pub external_id: Option<String>,
    pub id: String,
    #[serde(default, deserialize_with = "double_option")]
    pub metadata_admin: Option<Option<Value>>,
    #[serde(default, deserialize_with = "double_option")]
    pub metadata_public: Option<Option<Value>>,
    pub organization_id: Option<String>,
    pub recovery_addresses: Option<Vec<RecoveryIdentityAddress>>,
    #[serde(rename = "region")]
    _region: Option<RegionEnum>,
    pub schema_id: String,
    #[serde(rename = "schema_url")]
    _schema_url: String,
    pub state: Option<StateEnum>,
    pub state_changed_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub traits: Option<Value>,
    pub updated_at: Option<String>,
    pub verifiable_addresses: Option<Vec<VerifiableIdentityAddress>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IdentityCredentials {
    pub config: Option<Value>,
    pub created_at: Option<String>,
    pub identifiers: Option<Vec<String>>,
    #[serde(rename = "type")]
    _type: Option<MethodEnum>,
    pub updated_at: Option<String>,
    pub version: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct VerifiableIdentityAddress {
    pub created_at: Option<String>,
    pub id: Option<String>,
    pub status: String,
    pub updated_at: Option<String>,
    pub value: String,
    pub verified: bool,
    pub verified_at: Option<String>,
    pub via: ViaEnum,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryIdentityAddress {
    #[serde(rename = "break_glass_for_organization")]
    _break_glass_for_organization: Option<String>,
    pub created_at: Option<String>,
    pub id: Option<String>,
    pub updated_at: Option<String>,
    pub value: String,
    pub via: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Session {
    pub active: Option<bool>,
    pub authenticated_at: Option<String>,
    pub authentication_methods: Option<Vec<SessionAuthenticationMethod>>,
    pub authenticator_assurance_level: Option<AuthenticatorAssuranceLevel>,
    pub devices: Option<Vec<SessionDevice>>,
    pub expires_at: Option<String>,
    pub id: String,
    pub identity: Option<Box<Identity>>,
    pub issued_at: Option<String>,
    #[serde(rename = "tokenized")]
    _tokenized: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SessionAuthenticationMethod {
    pub aal: Option<AuthenticatorAssuranceLevel>,
    pub completed_at: Option<String>,
    pub method: Option<MethodEnum>,
    pub organization: Option<String>,
    pub provider: Option<String>,
    pub upstream_acr: Option<String>,
    pub upstream_amr: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SessionDevice {
    #[serde(rename = "id")]
    _id: String,
    pub ip_address: Option<String>,
    pub location: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryCodeForIdentity {
    #[serde(rename = "expires_at")]
    _expires_at: Option<String>,
    pub recovery_code: String,
    pub recovery_link: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryLinkForIdentity {
    #[serde(rename = "expires_at")]
    _expires_at: Option<String>,
    pub recovery_link: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteMySessionsCount {
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IdentitySchemaContainer {
    pub id: String,
    #[serde(rename = "schema")]
    _schema: Value,
}

#[derive(Debug, Deserialize)]
pub(super) struct GetVersion200Response {
    pub version: String,
}

/// A courier message, read only to be counted.
#[derive(Debug, Deserialize)]
pub(super) struct Message {
    #[serde(rename = "body")]
    _body: String,
    #[serde(rename = "channel")]
    _channel: Option<String>,
    #[serde(rename = "created_at")]
    _created_at: String,
    #[serde(rename = "dispatches")]
    _dispatches: Option<Vec<MessageDispatch>>,
    #[serde(rename = "id")]
    _id: String,
    #[serde(rename = "recipient")]
    _recipient: String,
    #[serde(rename = "send_count")]
    _send_count: i64,
    #[serde(rename = "status")]
    _status: CourierMessageStatus,
    #[serde(rename = "subject")]
    _subject: String,
    #[serde(rename = "template_type")]
    _template_type: TemplateTypeEnum,
    #[serde(rename = "type")]
    _type: CourierMessageType,
    #[serde(rename = "updated_at")]
    _updated_at: String,
}

#[derive(Debug, Deserialize)]
struct MessageDispatch {
    #[serde(rename = "created_at")]
    _created_at: String,
    #[serde(rename = "error")]
    _error: Option<Value>,
    #[serde(rename = "id")]
    _id: String,
    #[serde(rename = "message_id")]
    _message_id: String,
    #[serde(rename = "status")]
    _status: StatusEnum,
    #[serde(rename = "updated_at")]
    _updated_at: String,
}

// --- Requests ---------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct CreateIdentityBody<'a> {
    pub schema_id: &'a str,
    pub traits: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_addresses: Option<Vec<NewAddress<'a>>>,
}

#[derive(Serialize)]
pub(super) struct NewAddress<'a> {
    pub status: &'a str,
    pub value: &'a str,
    pub verified: bool,
    pub via: &'a str,
}

/// Metadata goes back as it was read: absent stays absent, `null` stays `null`.
#[derive(Serialize)]
pub(super) struct UpdateIdentityBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_admin: Option<Option<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_public: Option<Option<Value>>,
    pub schema_id: String,
    pub state: IdentityState,
    pub traits: Value,
}

/// One RFC 6902 operation.
#[derive(Debug, Serialize)]
pub(super) struct JsonPatchOp {
    pub op: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Serialize)]
pub(super) struct RecoveryCodeBody<'a> {
    pub identity_id: &'a str,
}

#[derive(Serialize)]
pub(super) struct RecoveryLinkBody<'a> {
    pub expires_in: &'a str,
    pub identity_id: &'a str,
}
