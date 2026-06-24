//! Socket wire types + length-prefixed codec shared by the Forseti Unix client
//! crates (daemon, NSS, authorizedkeys, PAM). Re-declared here so the client
//! never depends on the `forseti` server crate.
//!
//! Two protocols share the one socket and codec:
//! - `ClientRequest`/`ClientResponse` — FROZEN NSS/keys wire types; do not extend.
//! - `PamRequest`/`PamResponse` — the separate PAM device-auth protocol.

use std::io::{self, Read, Write};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub enum ClientRequest {
    PasswdByName(String),
    PasswdByUid(u32),
    PasswdAll,
    GroupByName(String),
    GroupByGid(u32),
    GroupAll,
    SshKeys(String),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub enum ClientResponse {
    Passwd(Option<PasswdEntry>),
    PasswdList(Vec<PasswdEntry>),
    Group(Option<GroupEntry>),
    GroupList(Vec<GroupEntry>),
    SshKeys(Vec<String>),
    Error(String),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub enum PamRequest {
    AuthBegin { username: String },
    AuthPoll { session_id: String },
    AccountAllowed { username: String },
    /// Offline-auth step: the daemon verifies `secret` locally against its
    /// keystore when the server is unreachable. Only reached after the daemon
    /// signalled `OfflineAvailable`.
    OfflineAuthStep { username: String, secret: String },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub enum PamResponse {
    /// Daemon started a device flow; PAM shows this and begins polling.
    ShowDeviceCode {
        session_id: String,
        verification_uri: String,
        user_code: String,
        interval: u32,
        expires_in: u32,
    },
    /// Approval still pending; PAM re-displays state and polls again.
    Pending,
    Success,
    Denied { reason: String },
    /// Username is not a Forseti-managed account → PAM maps to PAM_IGNORE.
    Unknown,
    /// Server unreachable but a usable offline credential exists; PAM prompts
    /// for the offline passphrase and sends `OfflineAuthStep`.
    OfflineAvailable,
    /// Offline passphrase verified locally → PAM_SUCCESS.
    OfflineSuccess,
    /// Offline passphrase rejected or gate refused → PAM_AUTH_ERR.
    OfflineDenied { reason: String },
}

// Sanity cap for the response direction; a passwd_all dump won't exceed this.
pub const MAX_FRAME: u32 = 8 * 1024 * 1024;

// Requests (NSS lookups, PAM opcodes) are tiny; cap the inbound direction far
// lower so a world-connectable peer can't make the server allocate megabytes.
pub const MAX_REQUEST_FRAME: u32 = 64 * 1024;

pub fn write_message<T: serde::Serialize, W: Write>(w: &mut W, msg: &T) -> io::Result<()> {
    let body =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_message<T: serde::de::DeserializeOwned, R: Read>(r: &mut R) -> io::Result<T> {
    read_message_capped(r, MAX_FRAME)
}

pub fn read_message_capped<T: serde::de::DeserializeOwned, R: Read>(
    r: &mut R,
    cap: u32,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds cap",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_json_roundtrip() {
        for req in [
            ClientRequest::PasswdByUid(1000),
            ClientRequest::GroupByName("staff".into()),
            ClientRequest::SshKeys("alice".into()),
            ClientRequest::PasswdAll,
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: ClientRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn response_json_roundtrip() {
        for resp in [
            ClientResponse::Passwd(Some(PasswdEntry {
                name: "alice".into(),
                uid: 1000,
                gid: 1000,
                gecos: "Alice".into(),
                dir: "/home/alice".into(),
                shell: "/bin/sh".into(),
            })),
            ClientResponse::Group(None),
            ClientResponse::SshKeys(vec!["ssh-ed25519 AAAA".into()]),
            ClientResponse::Error("not found".into()),
        ] {
            let json = serde_json::to_string(&resp).unwrap();
            let back: ClientResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(resp, back);
        }
    }

    #[test]
    fn framing_roundtrip() {
        let msg = ClientResponse::PasswdList(vec![PasswdEntry {
            name: "bob\nnewline".into(),
            uid: 2,
            gid: 2,
            gecos: String::new(),
            dir: "/home/bob".into(),
            shell: "/bin/sh".into(),
        }]);
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        let mut cur = Cursor::new(buf);
        let back: ClientResponse = read_message(&mut cur).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn pam_request_json_roundtrip() {
        for req in [
            PamRequest::AuthBegin {
                username: "alice".into(),
            },
            PamRequest::AuthPoll {
                session_id: "sess-123".into(),
            },
            PamRequest::AccountAllowed {
                username: "bob".into(),
            },
            PamRequest::OfflineAuthStep {
                username: "carol".into(),
                secret: "correct horse battery".into(),
            },
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: PamRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn pam_response_json_roundtrip() {
        for resp in [
            PamResponse::ShowDeviceCode {
                session_id: "sess-123".into(),
                verification_uri: "https://idp.example/device".into(),
                user_code: "WDJB-MJHT".into(),
                interval: 5,
                expires_in: 600,
            },
            PamResponse::Pending,
            PamResponse::Success,
            PamResponse::Denied {
                reason: "account disabled".into(),
            },
            PamResponse::Unknown,
            PamResponse::OfflineAvailable,
            PamResponse::OfflineSuccess,
            PamResponse::OfflineDenied {
                reason: "expired".into(),
            },
        ] {
            let json = serde_json::to_string(&resp).unwrap();
            let back: PamResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(resp, back);
        }
    }

    #[test]
    fn pam_framing_roundtrip() {
        let msg = PamResponse::ShowDeviceCode {
            session_id: "sess-456".into(),
            verification_uri: "https://idp.example/device".into(),
            user_code: "ABCD-EFGH".into(),
            interval: 5,
            expires_in: 900,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        let mut cur = Cursor::new(buf);
        let back: PamResponse = read_message(&mut cur).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn read_rejects_oversize_frame_without_allocating() {
        // Header claims 0xFFFFFFFF bytes; the cap check must fire before `vec![0u8; len]`.
        let header = u32::MAX.to_be_bytes();
        let mut cur = Cursor::new(header.to_vec());
        let err = read_message::<ClientResponse, _>(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn request_cap_rejects_frame_over_64k_but_under_max_frame() {
        // A length the response cap would accept but the request cap must reject.
        let len = MAX_REQUEST_FRAME + 1;
        assert!(len < MAX_FRAME);
        let header = len.to_be_bytes();
        let mut cur = Cursor::new(header.to_vec());
        let err =
            read_message_capped::<ClientRequest, _>(&mut cur, MAX_REQUEST_FRAME).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The dual-format dispatch on the socket is only safe because a serialized
    /// `PamRequest` never deserializes as a `ClientRequest` (the ungated path)
    /// and vice-versa. Externally-tagged serde keys on the variant names, so
    /// disjoint names give us that — but nothing in the type system enforces it.
    /// Pin both the name-disjointness and the cross-decode invariant here.
    #[test]
    fn client_and_pam_variants_are_mutually_undecodable() {
        let clients = [
            ClientRequest::PasswdByName("x".into()),
            ClientRequest::PasswdByUid(1),
            ClientRequest::PasswdAll,
            ClientRequest::GroupByName("x".into()),
            ClientRequest::GroupByGid(1),
            ClientRequest::GroupAll,
            ClientRequest::SshKeys("x".into()),
        ];
        let pams = [
            PamRequest::AuthBegin {
                username: "x".into(),
            },
            PamRequest::AuthPoll {
                session_id: "x".into(),
            },
            PamRequest::AccountAllowed {
                username: "x".into(),
            },
            PamRequest::OfflineAuthStep {
                username: "x".into(),
                secret: "x".into(),
            },
        ];

        for c in &clients {
            let json = serde_json::to_vec(c).unwrap();
            assert!(
                serde_json::from_slice::<PamRequest>(&json).is_err(),
                "{c:?} decoded as a PamRequest"
            );
        }
        for p in &pams {
            let json = serde_json::to_vec(p).unwrap();
            assert!(
                serde_json::from_slice::<ClientRequest>(&json).is_err(),
                "{p:?} decoded as a ClientRequest"
            );
        }

        let client_names = ["PasswdByName", "PasswdByUid", "PasswdAll", "GroupByName", "GroupByGid", "GroupAll", "SshKeys"];
        let pam_names = ["AuthBegin", "AuthPoll", "AccountAllowed", "OfflineAuthStep"];
        for c in client_names {
            assert!(!pam_names.contains(&c), "variant name {c} shared across enums");
        }
    }
}
