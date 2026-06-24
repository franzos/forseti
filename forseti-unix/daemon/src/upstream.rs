use anyhow::{Context, Result};
use base64::Engine;
use forseti_unix_proto::{ClientResponse, GroupEntry, PasswdEntry};
use reqwest::StatusCode;
use std::time::Duration;

/// HTTP client for the Forseti `/posix/v1/*` resolver, authenticated by
/// HTTP Basic `host_id:host_secret`.
pub struct Upstream {
    client: reqwest::Client,
    server_url: String,
    auth_header: String,
}

impl Upstream {
    pub fn new(
        server_url: &str,
        host_id: &str,
        host_secret: &str,
        timeout_secs: u64,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("building reqwest client")?;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("{host_id}:{host_secret}"));
        Ok(Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            auth_header: format!("Basic {creds}"),
        })
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.server_url, path);
        self.client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
    }

    pub async fn passwd_by_name(&self, name: &str) -> Result<ClientResponse> {
        let resp = self.get(&format!("/posix/v1/passwd/name/{name}")).await?;
        Ok(ClientResponse::Passwd(
            decode_single::<PasswdEntry>(resp).await?,
        ))
    }

    pub async fn passwd_by_uid(&self, uid: u32) -> Result<ClientResponse> {
        let resp = self.get(&format!("/posix/v1/passwd/uid/{uid}")).await?;
        Ok(ClientResponse::Passwd(
            decode_single::<PasswdEntry>(resp).await?,
        ))
    }

    pub async fn passwd_all(&self) -> Result<ClientResponse> {
        let resp = self.get("/posix/v1/passwd").await?;
        Ok(ClientResponse::PasswdList(
            decode_list::<PasswdEntry>(resp).await?,
        ))
    }

    pub async fn group_by_name(&self, name: &str) -> Result<ClientResponse> {
        let resp = self.get(&format!("/posix/v1/group/name/{name}")).await?;
        Ok(ClientResponse::Group(
            decode_single::<GroupEntry>(resp).await?,
        ))
    }

    pub async fn group_by_gid(&self, gid: u32) -> Result<ClientResponse> {
        let resp = self.get(&format!("/posix/v1/group/gid/{gid}")).await?;
        Ok(ClientResponse::Group(
            decode_single::<GroupEntry>(resp).await?,
        ))
    }

    pub async fn group_all(&self) -> Result<ClientResponse> {
        let resp = self.get("/posix/v1/group").await?;
        Ok(ClientResponse::GroupList(
            decode_list::<GroupEntry>(resp).await?,
        ))
    }

    pub async fn ssh_keys(&self, name: &str) -> Result<ClientResponse> {
        let resp = self
            .get(&format!("/posix/v1/authorized_keys/{name}"))
            .await?;
        match resp.status() {
            StatusCode::OK => {
                let body = resp.text().await.context("reading authorized_keys body")?;
                let keys = body
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect();
                Ok(ClientResponse::SshKeys(keys))
            }
            StatusCode::NOT_FOUND => Ok(ClientResponse::SshKeys(Vec::new())),
            other => anyhow::bail!("authorized_keys upstream status {other}"),
        }
    }
}

async fn decode_single<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<Option<T>> {
    match resp.status() {
        StatusCode::OK => Ok(Some(resp.json::<T>().await.context("decoding entry JSON")?)),
        StatusCode::NOT_FOUND => Ok(None),
        other => anyhow::bail!("upstream status {other}"),
    }
}

async fn decode_list<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<Vec<T>> {
    match resp.status() {
        StatusCode::OK => Ok(resp.json::<Vec<T>>().await.context("decoding list JSON")?),
        other => anyhow::bail!("upstream status {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn up(url: &str) -> Upstream {
        Upstream::new(url, "host", "secret", 3).unwrap()
    }

    #[tokio::test]
    async fn passwd_by_name_ok() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "alice", "uid": 2000000, "gid": 2000000,
                "gecos": "Alice", "dir": "/home/alice", "shell": "/bin/bash"
            })))
            .mount(&server)
            .await;

        let resp = up(&server.uri()).passwd_by_name("alice").await.unwrap();
        match resp {
            ClientResponse::Passwd(Some(e)) => {
                assert_eq!(e.name, "alice");
                assert_eq!(e.uid, 2000000);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn passwd_by_name_404_is_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/ghost"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let resp = up(&server.uri()).passwd_by_name("ghost").await.unwrap();
        assert_eq!(resp, ClientResponse::Passwd(None));
    }

    #[tokio::test]
    async fn passwd_all_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "a", "uid": 1, "gid": 1, "gecos": "", "dir": "/", "shell": "/bin/sh"}
            ])))
            .mount(&server)
            .await;
        let resp = up(&server.uri()).passwd_all().await.unwrap();
        match resp {
            ClientResponse::PasswdList(v) => assert_eq!(v.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn group_by_gid_ok() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/group/gid/2000000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "staff", "gid": 2000000, "members": ["alice", "bob"]
            })))
            .mount(&server)
            .await;
        let resp = up(&server.uri()).group_by_gid(2000000).await.unwrap();
        match resp {
            ClientResponse::Group(Some(g)) => {
                assert_eq!(g.name, "staff");
                assert_eq!(g.members, vec!["alice", "bob"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn ssh_keys_splits_lines() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/authorized_keys/alice"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("ssh-ed25519 AAAA one\n\nssh-rsa BBBB two\n"),
            )
            .mount(&server)
            .await;
        let resp = up(&server.uri()).ssh_keys("alice").await.unwrap();
        assert_eq!(
            resp,
            ClientResponse::SshKeys(vec![
                "ssh-ed25519 AAAA one".to_string(),
                "ssh-rsa BBBB two".to_string(),
            ])
        );
    }

    #[tokio::test]
    async fn ssh_keys_404_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/authorized_keys/ghost"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let resp = up(&server.uri()).ssh_keys("ghost").await.unwrap();
        assert_eq!(resp, ClientResponse::SshKeys(Vec::new()));
    }

    #[tokio::test]
    async fn server_error_is_err() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/posix/v1/passwd/name/alice"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(up(&server.uri()).passwd_by_name("alice").await.is_err());
    }
}
