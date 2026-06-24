use forseti_unix_proto::{ClientRequest, ClientResponse};
use forseti_unixd::Config;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tokio::net::UnixStream;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The on-the-wire format is proto's length-prefix (u32-BE len + JSON); we frame
/// it directly here rather than blocking the test runtime with proto's sync codec.
async fn round_trip(socket: &str, req: ClientRequest) -> ClientResponse {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    // Write framed request.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = serde_json::to_vec(&req).unwrap();
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();
    // Read framed response.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.unwrap();
    serde_json::from_slice(&buf).unwrap()
}

async fn wait_for_socket(path: &str) {
    for _ in 0..100 {
        if std::path::Path::new(path).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("socket never appeared at {path}");
}

#[tokio::test]
async fn end_to_end_cache_failsoft_and_no_ssh_cache() {
    let server = MockServer::start().await;

    // passwd/name/alice: serve OK once, then 500 forever after.
    Mock::given(method("GET"))
        .and(path("/posix/v1/passwd/name/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "alice", "uid": 2000000, "gid": 2000000,
            "gecos": "Alice", "dir": "/home/alice", "shell": "/bin/bash"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/posix/v1/passwd/name/alice"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    // SSH keys: count every hit so we can prove it is never cached.
    Mock::given(method("GET"))
        .and(path("/posix/v1/authorized_keys/alice"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("ssh-ed25519 AAAA alice\n"),
        )
        .expect(2)
        .mount(&server)
        .await;

    // 0700 tempdir for the socket; tempdir for the cache db.
    let sock_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(sock_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = sock_dir.path().join("unixd.sock");
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_db = cache_dir.path().join("cache.db");
    let creds_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(creds_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let creds_db = creds_dir.path().join("credentials.db");

    let cfg = Config {
        server_url: server.uri(),
        host_id: "host".into(),
        host_secret: "secret".into(),
        socket_path: socket_path.to_str().unwrap().to_string(),
        cache_db: cache_db.to_str().unwrap().to_string(),
        cache_ttl_secs: 3600,
        request_timeout_secs: 3,
        device_timeout_secs: 8,
        device_session_cap_secs: 90,
        credentials_db: creds_db.to_str().unwrap().to_string(),
        offline_lockout_max: 5,
        offline_poll_secs: 300,
        offline_max_lifetime_secs: 604_800,
    };

    let handle = tokio::spawn(forseti_unixd::run(cfg));
    let sock = socket_path.to_str().unwrap().to_string();
    wait_for_socket(&sock).await;

    // 1) First passwd lookup hits upstream, returns alice.
    let resp = round_trip(&sock, ClientRequest::PasswdByName("alice".into())).await;
    match resp {
        ClientResponse::Passwd(Some(ref e)) => {
            assert_eq!(e.name, "alice");
            assert_eq!(e.uid, 2000000);
        }
        other => panic!("unexpected {other:?}"),
    }

    // 2) Second lookup: upstream now 500s, but the cached value is served (fail-soft).
    let resp = round_trip(&sock, ClientRequest::PasswdByName("alice".into())).await;
    match resp {
        ClientResponse::Passwd(Some(ref e)) => assert_eq!(e.name, "alice"),
        other => panic!("expected cached alice, got {other:?}"),
    }

    // 3) SSH keys are never cached: two requests must both hit upstream (expect(2)).
    for _ in 0..2 {
        let resp = round_trip(&sock, ClientRequest::SshKeys("alice".into())).await;
        assert_eq!(
            resp,
            ClientResponse::SshKeys(vec!["ssh-ed25519 AAAA alice".to_string()])
        );
    }

    handle.abort();
    // wiremock `.expect(2)` is verified on MockServer drop.
}
