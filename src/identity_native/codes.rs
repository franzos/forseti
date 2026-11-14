//! Keyed MACs, one-time codes for verification and recovery, and session tokens.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{NativeBackend, random_bytes};
use crate::db_interact;
use crate::schema::{identity_codes, identity_mail_outbox};

/// Guesses one code allows; the submit after the last one fails even with the right code.
pub(super) const CODE_ATTEMPTS: i32 = 5;

/// How long a verification or recovery code works.
pub(super) fn code_lifespan() -> chrono::Duration {
    chrono::Duration::minutes(15)
}

/// What a one-time code proves; also the kind of the mail that carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Purpose {
    Verification,
    Recovery,
}

impl Purpose {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::Recovery => "recovery",
        }
    }

    pub(super) fn parse(s: &str) -> Option<Self> {
        [Self::Verification, Self::Recovery]
            .into_iter()
            .find(|p| p.as_str() == s)
    }
}

#[derive(Queryable, Selectable, Insertable, Debug, Clone)]
#[diesel(table_name = identity_codes)]
pub(super) struct CodeRow {
    id: String,
    flow_id: String,
    purpose: String,
    identity_id: String,
    /// Normalised address the code was mailed to; a verification code verifies exactly this one.
    address: String,
    code_mac: String,
    attempts: i32,
    expires_at: String,
    used_at: Option<String>,
    created_at: String,
}

/// A code row and the outbox row that mails it, built by [`NativeBackend::mailed_code`].
#[derive(Debug)]
pub(super) struct MailedCode {
    pub(super) code: CodeRow,
    pub(super) mail: super::mail::OutboxRow,
}

/// A code that matched and is now used up.
#[derive(Debug, PartialEq)]
pub(super) struct UsedCode {
    pub(super) identity_id: String,
    /// Normalised address the code was mailed to.
    pub(super) address: String,
}

impl NativeBackend {
    /// A fresh code for `purpose` on the flow, replacing the flow's earlier one, and the mail that
    /// carries it to `recipient`, written in one transaction. Wakes the mail worker.
    pub(super) async fn send_code(
        &self,
        flow_id: &str,
        purpose: Purpose,
        identity_id: &str,
        recipient: &str,
    ) -> Result<()> {
        self.store_code(flow_id, purpose, identity_id, recipient, true)
            .await?;
        self.wake_mail();
        Ok(())
    }

    /// [`send_code`](Self::send_code) without the mail: the code is returned to hand over another
    /// way. `address` is the identity's address, which the code is bound to like a mailed one.
    pub(super) async fn issue_code(
        &self,
        flow_id: &str,
        purpose: Purpose,
        identity_id: &str,
        address: &str,
    ) -> Result<String> {
        self.store_code(flow_id, purpose, identity_id, address, false)
            .await
    }

    /// A fresh code for `purpose` on the flow and the mail carrying it to `recipient`, for the
    /// caller to store in its own transaction; then [`wake_mail`](Self::wake_mail).
    pub(super) fn mailed_code(
        &self,
        flow_id: &str,
        purpose: Purpose,
        identity_id: &str,
        recipient: &str,
    ) -> MailedCode {
        let (code, row) = self.code_row(flow_id, purpose, identity_id, recipient);
        MailedCode {
            mail: self.outbox_row(purpose, identity_id, recipient, flow_id, &code),
            code: row,
        }
    }

    pub(super) fn wake_mail(&self) {
        self.mail_wake.notify_one();
    }

    fn code_row(
        &self,
        flow_id: &str,
        purpose: Purpose,
        identity_id: &str,
        recipient: &str,
    ) -> (String, CodeRow) {
        let code = new_numeric_code();
        let now = chrono::Utc::now();
        let row = CodeRow {
            id: uuid::Uuid::new_v4().to_string(),
            flow_id: flow_id.to_string(),
            purpose: purpose.as_str().to_string(),
            identity_id: identity_id.to_string(),
            address: super::store::email_norm(recipient),
            code_mac: code_mac(&self.keys.code_mac, flow_id, purpose.as_str(), &code),
            attempts: 0,
            expires_at: crate::db::rfc3339(now + code_lifespan()),
            used_at: None,
            created_at: crate::db::rfc3339(now),
        };
        (code, row)
    }

    async fn store_code(
        &self,
        flow_id: &str,
        purpose: Purpose,
        identity_id: &str,
        recipient: &str,
        mail: bool,
    ) -> Result<String> {
        let (code, row) = self.code_row(flow_id, purpose, identity_id, recipient);
        let mail = mail.then(|| self.outbox_row(purpose, identity_id, recipient, flow_id, &code));
        db_interact!(self.db, |c| {
            c.transaction::<_, diesel::result::Error, _>(|c| {
                diesel::delete(
                    identity_codes::table
                        .filter(identity_codes::flow_id.eq(&row.flow_id))
                        .filter(identity_codes::purpose.eq(&row.purpose)),
                )
                .execute(c)?;
                diesel::insert_into(identity_codes::table)
                    .values(&row)
                    .execute(c)?;
                if let Some(mail) = &mail {
                    diesel::insert_into(identity_mail_outbox::table)
                        .values(mail)
                        .execute(c)?;
                }
                Ok(())
            })
        })?;
        Ok(code)
    }

    /// Drop the flow's code for `purpose`, if it has one.
    pub(super) async fn retire_code(&self, flow_id: &str, purpose: Purpose) -> Result<()> {
        let (flow, kind) = (flow_id.to_string(), purpose.as_str());
        db_interact!(self.db, |c| {
            diesel::delete(
                identity_codes::table
                    .filter(identity_codes::flow_id.eq(&flow))
                    .filter(identity_codes::purpose.eq(kind)),
            )
            .execute(c)
        })?;
        Ok(())
    }

    /// Drop every code of the identity for `purpose`.
    pub(super) async fn retire_identity_codes(
        &self,
        identity_id: &str,
        purpose: Purpose,
    ) -> Result<()> {
        let (identity, kind) = (identity_id.to_string(), purpose.as_str());
        db_interact!(self.db, |c| {
            diesel::delete(
                identity_codes::table
                    .filter(identity_codes::identity_id.eq(&identity))
                    .filter(identity_codes::purpose.eq(kind)),
            )
            .execute(c)
        })?;
        Ok(())
    }

    /// Spend one guess on the flow's code for `purpose`. The identity and address the code was
    /// sent for when `code` is it and the code is unused, unexpired and within [`CODE_ATTEMPTS`];
    /// a match uses the code up.
    pub(super) async fn use_code(
        &self,
        flow_id: &str,
        purpose: Purpose,
        code: &str,
    ) -> Result<Option<UsedCode>> {
        let (flow, kind) = (flow_id.to_string(), purpose.as_str());
        // Each lost round means another guess was counted, so the code runs out within these.
        for _ in 0..CODE_ATTEMPTS {
            let (flow, now) = (flow.clone(), crate::db::now_rfc3339());
            let found: Option<CodeRow> = db_interact!(self.db, |c| {
                identity_codes::table
                    .filter(identity_codes::flow_id.eq(&flow))
                    .filter(identity_codes::purpose.eq(kind))
                    .filter(identity_codes::used_at.is_null())
                    .select(CodeRow::as_select())
                    .first(c)
                    .optional()
            })?;
            let Some(row) = found else {
                return Ok(None);
            };
            if row.attempts >= CODE_ATTEMPTS || row.expires_at <= now {
                return Ok(None);
            }
            let (id, seen) = (row.id.clone(), row.attempts);
            let counted = db_interact!(self.db, |c| {
                diesel::update(
                    identity_codes::table
                        .find(&id)
                        .filter(identity_codes::attempts.eq(seen))
                        .filter(identity_codes::used_at.is_null()),
                )
                .set(identity_codes::attempts.eq(seen + 1))
                .execute(c)
            })?;
            if counted == 0 {
                continue;
            }
            if !code_matches(&self.keys.code_mac, flow_id, kind, code, &row.code_mac) {
                return Ok(None);
            }
            let id = row.id.clone();
            let used = db_interact!(self.db, |c| {
                diesel::update(
                    identity_codes::table
                        .find(&id)
                        .filter(identity_codes::used_at.is_null()),
                )
                .set(identity_codes::used_at.eq(&now))
                .execute(c)
            })?;
            return Ok((used > 0).then_some(UsedCode {
                identity_id: row.identity_id,
                address: row.address,
            }));
        }
        Ok(None)
    }
}

/// HMAC-SHA256 key over `|`-joined parts.
pub(super) struct MacKey([u8; 32]);

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacKey(..)")
    }
}

impl MacKey {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn tag(&self, parts: &[&str]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key length");
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                mac.update(b"|");
            }
            mac.update(part.as_bytes());
        }
        mac.finalize().into_bytes().into()
    }

    /// Lowercase hex MAC for storage.
    pub(super) fn hex(&self, parts: &[&str]) -> String {
        hex::encode(self.tag(parts))
    }

    /// Constant-time check of `parts` against a stored [`MacKey::hex`] value.
    pub(super) fn matches_hex(&self, parts: &[&str], stored: &str) -> bool {
        let Ok(stored) = hex::decode(stored) else {
            return false;
        };
        bool::from(self.tag(parts).as_slice().ct_eq(&stored))
    }
}

/// Six decimal digits, uniform over `000000..=999999`.
pub(super) fn new_numeric_code() -> String {
    // Largest multiple of 10^6 that fits in u32; draws at or above it are rejected to avoid modulo bias.
    const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
    loop {
        let n = u32::from_be_bytes(random_bytes());
        if n < LIMIT {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

/// Stored MAC of a verification or recovery code, bound to its flow and purpose.
pub(super) fn code_mac(key: &MacKey, flow_id: &str, purpose: &str, code: &str) -> String {
    key.hex(&[flow_id, purpose, code.trim()])
}

pub(super) fn code_matches(
    key: &MacKey,
    flow_id: &str,
    purpose: &str,
    code: &str,
    stored: &str,
) -> bool {
    key.matches_hex(&[flow_id, purpose, code.trim()], stored)
}

/// A fresh session token: 32 random bytes, URL-safe base64 for the cookie.
pub(super) fn new_session_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Lowercase hex SHA-256 of the cookie value, the form stored in `identity_sessions.token_hash`.
pub(super) fn session_token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MacKey {
        MacKey::new([7; 32])
    }

    #[test]
    fn numeric_code_is_six_digits() {
        for _ in 0..200 {
            let code = new_numeric_code();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
    }

    #[test]
    fn code_mac_binds_flow_purpose_and_code() {
        let k = key();
        let stored = code_mac(&k, "flow-1", "verification", "123456");
        assert!(code_matches(
            &k,
            "flow-1",
            "verification",
            " 123456 ",
            &stored
        ));
        assert!(!code_matches(
            &k,
            "flow-2",
            "verification",
            "123456",
            &stored
        ));
        assert!(!code_matches(&k, "flow-1", "recovery", "123456", &stored));
        assert!(!code_matches(
            &k,
            "flow-1",
            "verification",
            "123457",
            &stored
        ));
        assert!(!code_matches(
            &MacKey::new([8; 32]),
            "flow-1",
            "verification",
            "123456",
            &stored
        ));
        assert!(!code_matches(
            &k,
            "flow-1",
            "verification",
            "123456",
            "not hex"
        ));
        assert!(!code_matches(
            &k,
            "flow-1",
            "verification",
            "123456",
            &stored[..62]
        ));
    }

    #[test]
    fn mac_matches_hmac_sha256_reference() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let reference = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            reference,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // A zero-padded 32-byte key is the same HMAC key as the 4-byte one.
        assert_eq!(
            MacKey::new(key).hex(&["what do ya want for nothing?"]),
            reference
        );
    }

    #[test]
    fn session_token_is_32_bytes_and_hash_is_sha256() {
        let token = new_session_token();
        assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 32);
        assert_ne!(token, new_session_token());
        assert_eq!(
            session_token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
