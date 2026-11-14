//! Seed the deterministic admin (verified address, password, TOTP) into a native Forseti's sqlite
//! file, the native counterpart of `infra/seed-admin.sh`. Same environment and defaults:
//! `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_ADMIN_TOTP_SECRET`; the database from
//! `FORSETI_DATABASE_URL` (default `./forseti.db`) and the cookie secret from the config named by
//! `FORSETI_CONFIG_PATH`. The database must exist: start Forseti once so it runs its migrations.

#[path = "../tests/support/native_seed.rs"]
mod native_seed;

use std::io::Write as _;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn main() -> std::io::Result<()> {
    let email = env_or("SEED_ADMIN_EMAIL", "admin@example.com");
    let password = env_or("SEED_ADMIN_PASSWORD", "Sup3rSecretAdminPw!9");
    let secret = env_or("SEED_ADMIN_TOTP_SECRET", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");

    let path = native_seed::db_path();
    if !path.exists() {
        eprintln!(
            "seed-admin-native: {} does not exist; start Forseti once so it creates the schema",
            path.display()
        );
        std::process::exit(1);
    }
    let conn = native_seed::open(&path);
    let cookie_secret = native_seed::cookie_secret();

    if let Some(id) = native_seed::identity_id_by_email(&conn, &email) {
        native_seed::delete_identity(&conn, &id);
        println!("seed-admin-native: deleted existing identity {id}");
    }
    let id = native_seed::create_identity(&conn, &email, None, None, true);
    native_seed::set_password(&conn, &id, &password);
    println!("seed-admin-native: created identity {id} ({email})");
    native_seed::plant_totp(&conn, &cookie_secret, &id, &secret);
    println!("seed-admin-native: planted TOTP credential for {id}");

    if let Ok(github_env) = std::env::var("GITHUB_ENV")
        && !github_env.is_empty()
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(github_env)?;
        writeln!(f, "FORSETI_ADMIN_TEST_EMAIL={email}")?;
        writeln!(f, "FORSETI_ADMIN_TEST_PASSWORD={password}")?;
        writeln!(f, "FORSETI_ADMIN_TEST_TOTP_SECRET={secret}")?;
    }
    println!("seed-admin-native: done. Export these for the test suites:");
    println!("  export FORSETI_ADMIN_TEST_EMAIL='{email}'");
    println!("  export FORSETI_ADMIN_TEST_PASSWORD='{password}'");
    println!("  export FORSETI_ADMIN_TEST_TOTP_SECRET='{secret}'");
    Ok(())
}
