//! Software authenticator for tests: ES256, `none` attestation, JSON shaped like a browser's `PublicKeyCredential`.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

pub(super) struct Authenticator {
    key: EcdsaKeyPair,
    pub(super) credential_id: Vec<u8>,
    /// Sets the UV flag in every response.
    pub(super) user_verified: bool,
    /// Keeps the user handle at registration and returns it on assertion.
    pub(super) resident_key: bool,
    /// Signature counter written into the next response as is.
    pub(super) sign_count: u32,
    /// `userHandle` of assertions; filled by a resident-key registration.
    pub(super) user_handle: Option<Vec<u8>>,
}

impl Authenticator {
    /// Discoverable, user-verifying, counter 0: a platform or synced passkey.
    pub(super) fn passkey() -> Self {
        Self::new(true, true)
    }

    /// Non-discoverable, presence only: a roaming security key.
    pub(super) fn security_key() -> Self {
        Self::new(false, false)
    }

    fn new(user_verified: bool, resident_key: bool) -> Self {
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap(),
            credential_id: super::random_bytes::<32>().to_vec(),
            user_verified,
            resident_key,
            sign_count: 0,
            user_handle: None,
        }
    }

    /// Answers `navigator.credentials.create` for `options` (`{"publicKey":{…}}`).
    pub(super) fn register(&mut self, rp_id: &str, origin: &str, options: &Value) -> Value {
        let public_key = &options["publicKey"];
        if self.resident_key {
            let user_id = public_key["user"]["id"]
                .as_str()
                .expect("options carry user.id");
            self.user_handle = Some(URL_SAFE_NO_PAD.decode(user_id).unwrap());
        }
        let client_data = client_data("webauthn.create", public_key, origin);

        let mut auth_data = self.auth_data(rp_id, FLAG_AT);
        auth_data.extend_from_slice(&[0; 16]);
        let id_len = u16::try_from(self.credential_id.len()).unwrap();
        auth_data.extend_from_slice(&id_len.to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&self.cose_key());

        let mut attestation = vec![0xa3];
        cbor_text(&mut attestation, "fmt");
        cbor_text(&mut attestation, "none");
        cbor_text(&mut attestation, "attStmt");
        attestation.push(0xa0);
        cbor_text(&mut attestation, "authData");
        cbor_bytes(&mut attestation, &auth_data);

        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
            },
            "clientExtensionResults": {},
        })
    }

    /// Answers `navigator.credentials.get` for `options` (`{"publicKey":{…}}`).
    pub(super) fn assert(&mut self, rp_id: &str, origin: &str, options: &Value) -> Value {
        let client_data = client_data("webauthn.get", &options["publicKey"], origin);
        let auth_data = self.auth_data(rp_id, 0);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(digest(&SHA256, &client_data).as_ref());
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        let user_handle = match &self.user_handle {
            Some(handle) if self.resident_key => Value::from(URL_SAFE_NO_PAD.encode(handle)),
            _ => Value::Null,
        };

        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.as_ref()),
                "userHandle": user_handle,
            },
            "clientExtensionResults": {},
        })
    }

    fn auth_data(&self, rp_id: &str, extra_flags: u8) -> Vec<u8> {
        let mut flags = FLAG_UP | extra_flags;
        if self.user_verified {
            flags |= FLAG_UV;
        }
        let mut out = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
        out.push(flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        out
    }

    /// COSE_Key map {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
    fn cose_key(&self) -> Vec<u8> {
        // Uncompressed SEC1 point: 0x04 || x || y.
        let point = self.key.public_key().as_ref();
        let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        cbor_bytes(&mut out, &point[1..33]);
        out.push(0x22);
        cbor_bytes(&mut out, &point[33..65]);
        out
    }
}

fn client_data(kind: &str, public_key: &Value, origin: &str) -> Vec<u8> {
    let challenge = public_key["challenge"]
        .as_str()
        .expect("options carry a challenge");
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))
    .unwrap()
}

fn cbor_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let major = major << 5;
    match len {
        0..=23 => out.push(major | u8::try_from(len).unwrap()),
        24..=0xff => out.extend_from_slice(&[major | 24, u8::try_from(len).unwrap()]),
        _ => {
            out.push(major | 25);
            out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}
