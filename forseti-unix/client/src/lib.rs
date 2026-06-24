//! Thin blocking client for the forseti-unixd socket. Shared by the
//! authorized-keys helper and the NSS `.so`, so it stays proto + libc only:
//! no tokio, no allocgetter-heavy crates, nothing that pulls a runtime into a
//! library libc dlopens into setuid sshd/sudo.
//!
//! Contract: any failure (no daemon, reset, timeout, malformed/short frame,
//! decode error) yields `None`. Callers treat `None` as ABSENT and fail open —
//! it must never hang or panic the host process.

use forseti_unix_proto as proto;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Query the daemon once (with a single reconnect on immediate failure).
/// Returns `None` on any error so the caller can fail open.
pub fn query(
    socket_path: &str,
    req: &proto::ClientRequest,
    timeout: Duration,
) -> Option<proto::ClientResponse> {
    query_msg(socket_path, req, timeout)
}

/// PAM device-auth round-trip: same wire codec + fail-soft `None` contract as
/// [`query`], over the `PamRequest`/`PamResponse` pair. Each call is one short
/// request/response; the long inter-poll wait lives in the PAM module, never on
/// the socket.
pub fn query_pam(
    socket_path: &str,
    req: &proto::PamRequest,
    timeout: Duration,
) -> Option<proto::PamResponse> {
    query_msg(socket_path, req, timeout)
}

/// Generic one-shot round-trip over the shared length-prefixed codec, with a
/// single reconnect on immediate failure. `None` on any error (no daemon, reset,
/// timeout, malformed/short frame, decode error) so callers fail open.
fn query_msg<Req, Resp>(socket_path: &str, req: &Req, timeout: Duration) -> Option<Resp>
where
    Req: serde::Serialize,
    Resp: serde::de::DeserializeOwned,
{
    match attempt(socket_path, req, timeout) {
        Some(resp) => Some(resp),
        // One reconnect: covers a daemon that dropped a previously-pooled conn.
        // For this one-shot helper it's just a fresh connect; harmless and cheap.
        None => attempt(socket_path, req, timeout),
    }
}

fn attempt<Req, Resp>(socket_path: &str, req: &Req, timeout: Duration) -> Option<Resp>
where
    Req: serde::Serialize,
    Resp: serde::de::DeserializeOwned,
{
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    // Encode the frame (u32-BE len + JSON) via proto, then push it with
    // MSG_NOSIGNAL — a dead socket must raise EPIPE, not SIGPIPE (whose default
    // disposition would KILL sshd/sudo). We can't SIG_IGN globally from a lib.
    let mut frame = Vec::new();
    proto::write_message(&mut frame, req).ok()?;
    send_all(&stream, &frame)?;

    proto::read_message(&mut stream).ok()
}

/// Write the whole buffer via `send(.., MSG_NOSIGNAL)`, looping over short
/// writes. Returns `None` on EPIPE / error / EOF.
fn send_all(stream: &UnixStream, buf: &[u8]) -> Option<()> {
    let fd = stream.as_raw_fd();
    let mut sent = 0usize;
    while sent < buf.len() {
        let chunk = &buf[sent..];
        // SAFETY: `fd` is a valid, open socket fd owned by `stream` for the
        // duration of this call; `chunk.as_ptr()`/`chunk.len()` describe a live,
        // in-bounds slice. MSG_NOSIGNAL suppresses SIGPIPE on a closed peer.
        let n = unsafe {
            libc::send(
                fd,
                chunk.as_ptr().cast::<libc::c_void>(),
                chunk.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n <= 0 {
            // 0 = peer closed; -1 = error (EPIPE/timeout/etc.). Either way: bail.
            return None;
        }
        sent += n as usize;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use forseti_unix_proto::{ClientRequest, ClientResponse};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::Instant;

    fn tmp_socket(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "forseti-client-test-{}-{}-{}.sock",
            name,
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn returns_canned_response() {
        let path = tmp_socket("ok");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req: ClientRequest = proto::read_message(&mut conn).unwrap();
            assert_eq!(req, ClientRequest::SshKeys("alice".into()));
            let resp = ClientResponse::SshKeys(vec!["ssh-ed25519 AAA...".into()]);
            proto::write_message(&mut conn, &resp).unwrap();
        });

        let resp = query(
            path.to_str().unwrap(),
            &ClientRequest::SshKeys("alice".into()),
            Duration::from_secs(2),
        );
        assert_eq!(
            resp,
            Some(ClientResponse::SshKeys(vec!["ssh-ed25519 AAA...".into()]))
        );
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pam_query_returns_canned_response() {
        use forseti_unix_proto::{PamRequest, PamResponse};
        let path = tmp_socket("pam");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req: PamRequest = proto::read_message(&mut conn).unwrap();
            assert_eq!(
                req,
                PamRequest::AuthBegin {
                    username: "alice".into()
                }
            );
            let resp = PamResponse::ShowDeviceCode {
                session_id: "s1".into(),
                verification_uri: "https://idp/device".into(),
                user_code: "WXYZ-1234".into(),
                interval: 5,
                expires_in: 600,
            };
            proto::write_message(&mut conn, &resp).unwrap();
        });

        let resp = query_pam(
            path.to_str().unwrap(),
            &PamRequest::AuthBegin {
                username: "alice".into(),
            },
            Duration::from_secs(2),
        );
        assert!(matches!(resp, Some(PamResponse::ShowDeviceCode { .. })));
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_server_returns_none_without_hanging() {
        let path = tmp_socket("absent");
        // Nothing bound here.
        let start = Instant::now();
        let resp = query(
            path.to_str().unwrap(),
            &ClientRequest::SshKeys("alice".into()),
            Duration::from_millis(500),
        );
        assert_eq!(resp, None);
        // Connect to a nonexistent socket fails immediately; nowhere near timeout.
        assert!(start.elapsed() < Duration::from_secs(2), "should not hang");
    }

    #[test]
    fn slow_server_times_out_within_bound() {
        let path = tmp_socket("slow");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            // Accept then go silent past the client's read timeout.
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                let _ = conn.read(&mut buf); // drain the request frame
                thread::sleep(Duration::from_secs(5));
                let _ = conn.write_all(b"\0"); // too late; client already bailed
            }
        });

        let timeout = Duration::from_millis(300);
        let start = Instant::now();
        let resp = query(
            path.to_str().unwrap(),
            &ClientRequest::SshKeys("alice".into()),
            timeout,
        );
        let elapsed = start.elapsed();
        assert_eq!(resp, None);
        // query does one reconnect, so allow a couple of timeout cycles, but it
        // must be bounded — proving it can't wedge sshd indefinitely.
        assert!(
            elapsed < timeout * 8,
            "timed out too slowly: {elapsed:?} (timeout {timeout:?})"
        );
        // Detach the server thread; it's sleeping and we don't want to block.
        drop(server);
        let _ = std::fs::remove_file(&path);
    }
}
