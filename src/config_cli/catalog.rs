//! `config status` reads: a static catalog of the settings the `config`
//! subcommands can write, paired with a live probe of each one's current
//! state. Values themselves never leave this module — only fingerprints
//! (`io::fingerprint`) and presence/length facts reach the operator.

use serde_yaml_ng::Value;
use toml_edit::DocumentMut;

use super::check::{extract_hook_token, webhook_token_entries, PLACEHOLDER_TOKENS};
use super::init::is_dev_smtp;
use super::io::fingerprint;
use super::redact_uri;
use super::yamlutil::{dig, dig_str, is_placeholder, secret_entries};

pub(crate) struct Setting {
    pub key: &'static str,
    pub group: &'static str,
    pub title: &'static str,
    // Rendered by a later task (the interactive menu / `config <setting> --help`
    // prose); `config status` itself only needs key/group/title/targets today.
    #[allow(dead_code)]
    pub description: &'static str,
    pub targets: &'static [&'static str],
}

pub(crate) const SETTINGS: &[Setting] = &[
    Setting {
        key: "oidc.google",
        group: "Sign-in providers",
        title: "Google sign-in",
        description: "Registers Forseti as an upstream OIDC client of Google. Create an OAuth 2.0 Client ID at the Google Cloud console, set the authorized redirect URI to `https://<kratos-public-host>/self-service/methods/oidc/callback/google`, then paste the client ID and secret into `selfservice.methods.oidc.config.providers` in kratos.yml. `mapper_url` must point at a `file://` jsonnet mapper next to kratos.yml that maps `claims.email` (and ideally `claims.email_verified`) onto the identity's traits — Google does mark verified emails, but a mapper that copies `email` without gating on `email_verified` still lets anyone who controls an unverified alias claim the matching Forseti account.",
        targets: &["kratos.yml"],
    },
    Setting {
        key: "oidc.github",
        group: "Sign-in providers",
        title: "GitHub sign-in",
        description: "Registers Forseti as an upstream OIDC client of GitHub. Create an OAuth App at github.com/settings/developers, set the callback URL to `https://<kratos-public-host>/self-service/methods/oidc/callback/github`, request the `user:email` scope so the id_token carries an email at all, then paste the client ID and secret into kratos.yml. GitHub's claims don't reliably carry `email_verified` — treat every GitHub-sourced email as unverified in the mapper and require the user to verify it through Forseti's own verification flow before trusting it for account linking.",
        targets: &["kratos.yml"],
    },
    Setting {
        key: "oidc.microsoft",
        group: "Sign-in providers",
        title: "Microsoft sign-in",
        description: "Registers Forseti as an upstream OIDC client of Microsoft Entra ID (Azure AD). Register an app at the Entra admin center, set the redirect URI to `https://<kratos-public-host>/self-service/methods/oidc/callback/microsoft`, then paste the client ID and secret into kratos.yml. `microsoft_tenant` must name a specific tenant ID (or the `organizations`/`consumers` pseudo-tenants if that's genuinely intended) — the default `common` accepts sign-in from any Azure AD tenant or personal Microsoft account, not just your own organization.",
        targets: &["kratos.yml"],
    },
    Setting {
        key: "audit.webhook-token",
        group: "Secrets & delivery",
        title: "Audit webhook token",
        description: "Shared bearer token that authenticates Kratos's flow webhooks to Forseti's `/internal/audit/kratos` receiver. Forseti reads it from `[audit].webhook_token`; Kratos sends it from the `auth.config.value` field on every `web_hook` in kratos.yml. Forseti refuses to boot when it's unset. `webhook_token` accepts either a single string or an array (an accept list): to rotate without a 401 window, add the new token as an additional array entry, restart Forseti, update every `web_hook` in kratos.yml to the new value and restart/HUP Kratos, then prune the old entry once it's no longer presented. There's no online rotation on the Kratos side — Kratos's config loader doesn't support env-var overrides for fields inside arrays (ory/kratos#2663), so kratos.yml has to be edited and Kratos restarted directly.",
        targets: &["kratos.yml", "config.toml"],
    },
    Setting {
        key: "kratos.secrets",
        group: "Secrets & delivery",
        title: "Kratos secrets (cookie / cipher)",
        description: "`secrets.cookie` signs Kratos's session and CSRF cookies (at least 16 random characters); `secrets.cipher` encrypts values at rest with xchacha20-poly1305 and must be exactly 32 characters — the algorithm's key size, not a style preference. Kratos's rotation convention applies to both: prepend the new secret as the first list entry and keep the old one(s) in place, since the first entry signs/encrypts new values while every entry remains valid to verify/decrypt older ones. Once nothing references an old secret anymore, prune it from the list.",
        targets: &["kratos.yml"],
    },
    Setting {
        key: "hydra.system",
        group: "Secrets & delivery",
        title: "Hydra secrets (system) + pairwise salt",
        description: "`secrets.system` encrypts everything in Hydra's database — consent grants, refresh tokens. Rotate it the same rolling way as Kratos's secrets: prepend the new value and keep the old one for decryption until nothing depends on it. `oidc.subject_identifiers.pairwise.salt` is a different kind of secret: it derives every pairwise subject identifier Hydra has ever issued, per client. Changing it changes ALL pairwise `sub` values permanently — any downstream app that matched a user by their old pairwise subject will see what looks like a brand-new account after rotation. Only rotate the pairwise salt deliberately, with the affected client applications aware.",
        targets: &["hydra.yml"],
    },
    Setting {
        key: "kratos.courier-smtp",
        group: "Secrets & delivery",
        title: "Courier SMTP (mail delivery)",
        description: "`courier.smtp.connection_uri` is where Kratos sends recovery, verification, and (optionally) passwordless-code mail. The playground default points at a throwaway dev catcher (mailcrab/mailslurper) that never reaches a real inbox — self-service recovery and verification silently do nothing until this is pointed at a production SMTP provider. `from_address`/`from_name` are optional and, when set, are written alongside `connection_uri`.",
        targets: &["kratos.yml"],
    },
];

#[derive(serde::Serialize)]
pub(crate) struct SettingStatus {
    pub key: &'static str,
    pub state: String,
    pub detail: String,
}

/// Probes = check findings mapped per setting + presence probes for optional
/// settings. Reads only presence/length/fingerprint facts, never raw secret
/// values, and does no filesystem access beyond what the caller already
/// loaded (no mapper-file reads here — that's `check_oidc_providers`'s job).
pub(crate) fn status_of(
    kratos: &Value,
    hydra: &Value,
    forseti_toml: Option<&DocumentMut>,
) -> Vec<SettingStatus> {
    SETTINGS
        .iter()
        .map(|s| {
            let (state, detail) = match s.key {
                "oidc.google" => provider_status(kratos, "google"),
                "oidc.github" => provider_status(kratos, "github"),
                "oidc.microsoft" => provider_status(kratos, "microsoft"),
                "audit.webhook-token" => webhook_token_status(kratos, forseti_toml),
                "kratos.secrets" => kratos_secrets_status(kratos),
                "hydra.system" => hydra_system_status(hydra),
                "kratos.courier-smtp" => courier_smtp_status(kratos),
                other => (
                    "missing".to_string(),
                    format!("no status probe wired up for `{other}`"),
                ),
            };
            SettingStatus {
                key: s.key,
                state,
                detail,
            }
        })
        .collect()
}

fn provider_status(kratos: &Value, id: &str) -> (String, String) {
    let providers = dig(
        kratos,
        &["selfservice", "methods", "oidc", "config", "providers"],
    )
    .and_then(Value::as_sequence);
    let Some(provider) = providers
        .into_iter()
        .flatten()
        .find(|p| dig_str(p, &["id"]) == Some(id))
    else {
        return (
            "missing".to_string(),
            "no provider entry in kratos.yml".to_string(),
        );
    };

    let client_id_ok = dig_str(provider, &["client_id"]).is_some_and(|v| !is_placeholder(v));
    let client_secret = dig_str(provider, &["client_secret"]);
    let client_secret_ok = client_secret.is_some_and(|v| !is_placeholder(v));
    if !client_id_ok || !client_secret_ok {
        return (
            "placeholder".to_string(),
            "client_id/client_secret unset or still a placeholder".to_string(),
        );
    }
    let fp = client_secret.map(fingerprint).unwrap_or_default();
    (
        "ok".to_string(),
        format!("configured; client_secret sha256[:8]={fp}"),
    )
}

fn webhook_token_status(kratos: &Value, doc: Option<&DocumentMut>) -> (String, String) {
    let Some(doc) = doc else {
        return (
            "missing".to_string(),
            "config.toml not found; cannot verify [audit].webhook_token".to_string(),
        );
    };
    let entries = webhook_token_entries(doc);
    if entries.is_empty() {
        return (
            "missing".to_string(),
            "[audit].webhook_token is unset".to_string(),
        );
    }
    if entries
        .iter()
        .any(|t| PLACEHOLDER_TOKENS.contains(&t.as_str()))
    {
        return (
            "dev".to_string(),
            "accept list still contains the public dev-playground token".to_string(),
        );
    }
    if entries.iter().any(|t| is_placeholder(t)) {
        return (
            "placeholder".to_string(),
            "accept list entry looks like an unfilled placeholder".to_string(),
        );
    }

    let hook_token = extract_hook_token(kratos);
    if let Some(hook_token) = &hook_token {
        if !entries.iter().any(|e| e == hook_token) {
            return (
                "fail".to_string(),
                "kratos.yml's hook token isn't in [audit].webhook_token — audit webhook calls will 401"
                    .to_string(),
            );
        }
    }
    if entries.len() > 1 {
        return (
            "rotation-pending".to_string(),
            format!(
                "{} accept-list entries; restart + prune pending",
                entries.len()
            ),
        );
    }
    (
        "ok".to_string(),
        format!("sha256[:8]={}", fingerprint(&entries[0])),
    )
}

fn kratos_secrets_status(kratos: &Value) -> (String, String) {
    let cookie = secret_entries(kratos, &["secrets", "cookie"]);
    let cipher = secret_entries(kratos, &["secrets", "cipher"]);
    if cookie.is_empty() || cipher.is_empty() {
        return (
            "missing".to_string(),
            "secrets.cookie/secrets.cipher unset".to_string(),
        );
    }
    if cookie.iter().any(|s| is_placeholder(s)) || cipher.iter().any(|s| is_placeholder(s)) {
        return (
            "placeholder".to_string(),
            "cookie/cipher still carries a placeholder value".to_string(),
        );
    }
    if cookie.iter().any(|s| s.len() < 16) || cipher.iter().any(|s| s.len() != 32) {
        return (
            "fail".to_string(),
            "length requirement not met (cookie >=16 chars, cipher ==32 chars)".to_string(),
        );
    }
    if cookie.len() > 3 || cipher.len() > 3 {
        return (
            "warn".to_string(),
            "more than 3 entries; prune stale rotation entries".to_string(),
        );
    }
    (
        "ok".to_string(),
        format!(
            "cookie sha256[:8]={}, cipher sha256[:8]={}",
            fingerprint(cookie[0]),
            fingerprint(cipher[0])
        ),
    )
}

fn hydra_system_status(hydra: &Value) -> (String, String) {
    let system = secret_entries(hydra, &["secrets", "system"]);
    let pairwise = dig_str(hydra, &["oidc", "subject_identifiers", "pairwise", "salt"]);
    let Some(pairwise) = pairwise else {
        return (
            "missing".to_string(),
            "secrets.system or oidc.subject_identifiers.pairwise.salt unset".to_string(),
        );
    };
    if system.is_empty() {
        return (
            "missing".to_string(),
            "secrets.system or oidc.subject_identifiers.pairwise.salt unset".to_string(),
        );
    }
    if system.iter().any(|s| is_placeholder(s)) || is_placeholder(pairwise) {
        return (
            "placeholder".to_string(),
            "system secret or pairwise salt still carries a placeholder value".to_string(),
        );
    }
    if system.iter().any(|s| s.len() < 16) {
        return (
            "fail".to_string(),
            "secrets.system entry shorter than 16 chars".to_string(),
        );
    }
    if system.len() > 3 {
        return (
            "warn".to_string(),
            "secrets.system has more than 3 entries; prune stale rotation entries".to_string(),
        );
    }
    (
        "ok".to_string(),
        format!(
            "system sha256[:8]={}, pairwise-salt sha256[:8]={}",
            fingerprint(system[0]),
            fingerprint(pairwise)
        ),
    )
}

fn courier_smtp_status(kratos: &Value) -> (String, String) {
    match dig_str(kratos, &["courier", "smtp", "connection_uri"]) {
        None => (
            "missing".to_string(),
            "courier.smtp.connection_uri unset".to_string(),
        ),
        Some(uri) if is_placeholder(uri) => (
            "placeholder".to_string(),
            "connection_uri still a CHANGEME placeholder".to_string(),
        ),
        Some(uri) if is_dev_smtp(uri) => (
            "dev".to_string(),
            format!("{} (dev mailbox)", redact_uri(uri)),
        ),
        Some(uri) => ("ok".to_string(), redact_uri(uri)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(statuses: &'a [SettingStatus], key: &str) -> &'a SettingStatus {
        statuses
            .iter()
            .find(|s| s.key == key)
            .unwrap_or_else(|| panic!("no status for {key}"))
    }

    // A pair shaped like `config-init`'s output: real URLs/DSN/SMTP, fresh
    // 32-char secrets, no OIDC providers (init never writes any).
    const INIT_LIKE_KRATOS: &str = r#"
selfservice:
  methods:
    password:
      enabled: true
secrets:
  cookie:
    - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  cipher:
    - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
courier:
  smtp:
    connection_uri: smtps://user:pass@smtp.example.com:465
"#;
    const INIT_LIKE_HYDRA: &str = r#"
secrets:
  system:
    - cccccccccccccccccccccccccccccccc
oidc:
  subject_identifiers:
    pairwise:
      salt: dddddddddddddddddddddddddddddddd
"#;

    #[test]
    fn status_of_reports_seven_settings() {
        assert_eq!(SETTINGS.len(), 7);
    }

    #[test]
    fn init_like_pair_has_no_oidc_providers_configured() {
        let kratos_v: Value = serde_yaml_ng::from_str(INIT_LIKE_KRATOS).unwrap();
        let hydra_v: Value = serde_yaml_ng::from_str(INIT_LIKE_HYDRA).unwrap();

        let doc: DocumentMut = "[audit]\nwebhook_token = \"a-real-token\"\n"
            .parse()
            .expect("toml parses");

        let statuses = status_of(&kratos_v, &hydra_v, Some(&doc));

        assert_eq!(find(&statuses, "oidc.google").state, "missing");
        assert_eq!(find(&statuses, "oidc.github").state, "missing");
        assert_eq!(find(&statuses, "oidc.microsoft").state, "missing");

        let webhook = find(&statuses, "audit.webhook-token");
        assert!(
            webhook.state == "ok" || webhook.state == "placeholder",
            "expected ok or placeholder, got {}",
            webhook.state
        );
    }

    #[test]
    fn status_of_without_forseti_toml_is_missing() {
        let kratos: Value = serde_yaml_ng::from_str("selfservice: {}").unwrap();
        let hydra: Value = serde_yaml_ng::from_str("secrets: {}").unwrap();
        let statuses = status_of(&kratos, &hydra, None);
        assert_eq!(find(&statuses, "audit.webhook-token").state, "missing");
    }

    #[test]
    fn json_output_round_trips_through_serde() {
        let kratos: Value = serde_yaml_ng::from_str("selfservice: {}").unwrap();
        let hydra: Value = serde_yaml_ng::from_str("secrets: {}").unwrap();
        let statuses = status_of(&kratos, &hydra, None);

        let json = serde_json::to_string(&statuses).expect("serializes");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), SETTINGS.len());
        assert!(arr[0].get("key").is_some());
        assert!(arr[0].get("state").is_some());
        assert!(arr[0].get("detail").is_some());
    }
}
