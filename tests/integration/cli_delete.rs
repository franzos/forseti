//! `forseti delete-identity`: the admin deletion CLI, spawned as a process
//! against the CI config and the same sqlite file the portal uses.

use crate::common::*;
use std::process::{Command, Output, Stdio};

fn delete_identity_cmd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_forseti"))
        .arg("delete-identity")
        .args(args)
        .env("FORSETI_CONFIG_PATH", "config.ci.toml")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .output()
        .expect("spawn forseti delete-identity")
}

async fn kratos_has_identity(id: &str) -> bool {
    browser_client()
        .get(format!("{KRATOS_ADMIN}/admin/identities/{id}"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[tokio::test]
async fn cli_delete_with_yes_removes_the_identity_and_its_rows() {
    assert!(portal_reachable().await);
    let user = register_test_user("cli-delete").await;
    let _ = user
        .client
        .get(format!("{PORTAL}/"))
        .send()
        .await
        .expect("warm-up");
    let id = user.identity_id.clone();

    let out = delete_identity_cmd(&[&id, "--yes"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("removed"), "stdout: {stdout}");
    assert!(stdout.contains("left as orphans: none"), "stdout: {stdout}");

    assert!(!kratos_has_identity(&id).await, "identity must be gone");
    let left = rows_referencing(&id, &user.email);
    assert!(left.is_empty(), "rows left: {left:?}");
    let row = latest_audit_event("admin.identity.deleted", &id).expect("audit row");
    assert_eq!(row.severity, "critical");
    assert_eq!(row.actor_kind, "system");
    assert_eq!(row.metadata["reason"], "cli", "metadata: {}", row.metadata);
    assert_eq!(
        row.metadata["orphan_count"], 0,
        "metadata: {}",
        row.metadata
    );
}

#[tokio::test]
async fn cli_delete_without_yes_off_a_terminal_exits_2_and_keeps_the_identity() {
    assert!(portal_reachable().await);
    let user = register_test_user("cli-delete-notty").await;
    let id = user.identity_id.clone();

    let out = delete_identity_cmd(&[&id]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("--yes"), "stderr: {stderr}");
    assert!(kratos_has_identity(&id).await, "identity must still exist");
    assert!(latest_audit_event("admin.identity.deleted", &id).is_none());

    user.cleanup().await;
}
