//! Forseti-owned database (separate from the Kratos/Hydra Postgres): pool init, backend selection, migrations.
//! Two first-class backends, sqlite (zero-ops self-host default) and Postgres (multi-instance). Sync `diesel`
//! runs on `deadpool-diesel`'s blocking worker so both backends share one query path.

use deadpool_diesel::{
    postgres::{Manager as PgManager, Pool as PgPool, Runtime as PgRuntime},
    sqlite::{
        Hook, HookError, Manager as SqliteManager, Pool as SqlitePool, Runtime as SqliteRuntime,
    },
};
use diesel::{pg::PgConnection, sql_types::BigInt, sqlite::SqliteConnection, RunQueryDsl};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

/// Stable int8 key for `pg_advisory_lock` so concurrent replicas booting
/// simultaneously serialise their migration runs instead of deadlocking or
/// partially applying schema.
const PG_MIGRATION_LOCK_KEY: i64 = fnv1a_64("forseti_migrations") as i64;

const fn fnv1a_64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
}

use crate::config::{DatabaseBackend, DatabaseConfig};

/// Migrations live in two parallel folders so each backend can carry its own
/// dialect-specific SQL (sqlite's `WITHOUT ROWID`, postgres's `JSONB` /
/// triggers, etc). The Rust API is identical via diesel's query DSL.
const SQLITE_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
const POSTGRES_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgres");

/// SQLite has one writer at a time; more connections only deepen the write-lock queue and burn blocking workers.
const SQLITE_MAX_POOL: usize = 8;

/// Pool handle stored in `AppState`; both variants share one Rust query API via `interact`.
#[derive(Clone)]
pub enum DbPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl DbPool {
    /// Initialise a pool from `[database]` config. Picks the backend from the
    /// URL scheme. Sqlite URLs may use a `sqlite://` prefix or a raw path; both work.
    pub fn init(cfg: &DatabaseConfig) -> anyhow::Result<Self> {
        match cfg.backend() {
            DatabaseBackend::Sqlite => {
                let path = sqlite_path(&cfg.url);
                #[cfg(unix)]
                restrict_sqlite_permissions(&path)?;
                let manager = SqliteManager::new(path, SqliteRuntime::Tokio1);
                let pool = SqlitePool::builder(manager)
                    .max_size(SQLITE_MAX_POOL)
                    .post_create(Hook::async_fn(|conn, _metrics| {
                        Box::pin(async move {
                            conn.interact(|c: &mut SqliteConnection| {
                                // WAL so readers/writers don't block; busy_timeout waits instead of SQLITE_BUSY; FKs off by default in sqlite.
                                diesel::sql_query("PRAGMA journal_mode = WAL").execute(c)?;
                                diesel::sql_query("PRAGMA busy_timeout = 5000").execute(c)?;
                                diesel::sql_query("PRAGMA foreign_keys = ON").execute(c)?;
                                Ok::<_, diesel::result::Error>(())
                            })
                            .await
                            .map_err(|e| {
                                HookError::message(format!("sqlite PRAGMA interact panic: {e:?}"))
                            })?
                            .map_err(|e| {
                                HookError::message(format!("sqlite PRAGMA failed: {e}"))
                            })?;
                            Ok(())
                        })
                    }))
                    .build()?;
                Ok(DbPool::Sqlite(pool))
            }
            DatabaseBackend::Postgres => {
                let manager = PgManager::new(cfg.url.clone(), PgRuntime::Tokio1);
                let pool = PgPool::builder(manager).build()?;
                Ok(DbPool::Postgres(pool))
            }
        }
    }

    /// Which backend this pool is talking to. Drives the production-shape
    /// banner on `/admin/status`.
    pub fn backend(&self) -> DatabaseBackend {
        match self {
            DbPool::Sqlite(_) => DatabaseBackend::Sqlite,
            DbPool::Postgres(_) => DatabaseBackend::Postgres,
        }
    }

    /// Run the embedded migrations for the active backend. Idempotent: diesel's harness skips applied ones.
    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        match self {
            DbPool::Sqlite(pool) => {
                let conn = pool.get().await?;
                conn.interact(|c: &mut SqliteConnection| {
                    c.run_pending_migrations(SQLITE_MIGRATIONS)
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("sqlite migrations: {e}"))
                })
                .await
                .map_err(|e| anyhow::anyhow!("sqlite interact: {e}"))??;
            }
            DbPool::Postgres(pool) => {
                let conn = pool.get().await?;
                conn.interact(|c: &mut PgConnection| {
                    diesel::sql_query("SELECT pg_advisory_lock($1)")
                        .bind::<BigInt, _>(PG_MIGRATION_LOCK_KEY)
                        .execute(c)
                        .map_err(|e| anyhow::anyhow!("postgres advisory lock: {e}"))?;
                    let result = c
                        .run_pending_migrations(POSTGRES_MIGRATIONS)
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("postgres migrations: {e}"));
                    let unlock = diesel::sql_query("SELECT pg_advisory_unlock($1)")
                        .bind::<BigInt, _>(PG_MIGRATION_LOCK_KEY)
                        .execute(c)
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("postgres advisory unlock: {e}"));
                    match (result, unlock) {
                        (Err(e), _) => Err(e),
                        (Ok(()), Err(e)) => Err(e),
                        (Ok(()), Ok(())) => Ok(()),
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("postgres interact: {e}"))??;
            }
        }
        Ok(())
    }

    /// Open a connection and run a smoke probe (`SELECT 1`). Called once at
    /// boot so we surface bad URLs / unreachable Postgres before the first
    /// request hits a handler.
    pub async fn ping(&self) -> anyhow::Result<()> {
        use diesel::prelude::*;
        match self {
            DbPool::Sqlite(pool) => {
                let conn = pool.get().await?;
                conn.interact(|c: &mut SqliteConnection| {
                    diesel::sql_query("SELECT 1").execute(c).map(|_| ())
                })
                .await
                .map_err(|e| anyhow::anyhow!("sqlite ping interact: {e}"))??;
            }
            DbPool::Postgres(pool) => {
                let conn = pool.get().await?;
                conn.interact(|c: &mut PgConnection| {
                    diesel::sql_query("SELECT 1").execute(c).map(|_| ())
                })
                .await
                .map_err(|e| anyhow::anyhow!("postgres ping interact: {e}"))??;
            }
        }
        Ok(())
    }
}

/// Dispatch a sync diesel closure over whichever backend `DbPool` holds. The body expands once per backend,
/// so any DSL expression compiling against both `SqliteConnection` and `PgConnection` works. Deadpool/interact
/// errors collapse into `anyhow`.
///
/// ```ignore
/// db_interact!(db, |conn| {
///     diesel::insert_into(t::table).values(&rows).execute(conn)
/// }).await?
/// ```
#[macro_export]
macro_rules! db_interact {
    ($db:expr, |$conn:ident| $body:block) => {{
        match &$db {
            $crate::db::DbPool::Sqlite(pool) => {
                let conn = pool
                    .get()
                    .await
                    .map_err(|e| anyhow::anyhow!("sqlite pool: {e}"))?;
                conn.interact(move |$conn: &mut diesel::sqlite::SqliteConnection| $body)
                    .await
                    .map_err(|e| anyhow::anyhow!("sqlite interact: {e}"))?
            }
            $crate::db::DbPool::Postgres(pool) => {
                let conn = pool
                    .get()
                    .await
                    .map_err(|e| anyhow::anyhow!("postgres pool: {e}"))?;
                conn.interact(move |$conn: &mut diesel::pg::PgConnection| $body)
                    .await
                    .map_err(|e| anyhow::anyhow!("postgres interact: {e}"))?
            }
        }
    }};
}

/// The sqlite file holds secrets (transient secret_reveals payloads, invite
/// tokens, audit log), so it must not be world-readable. Pre-create the db
/// file `0600` when missing — sqlite gives `-wal`/`-shm` the same mode as the
/// main file — and tighten the main file plus any existing siblings on
/// pre-existing deployments. A zero-length file is a valid empty sqlite db.
#[cfg(unix)]
fn restrict_sqlite_permissions(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if path == ":memory:" {
        return Ok(());
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("create sqlite db {path:?}: {e}"))?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms.clone())
        .map_err(|e| anyhow::anyhow!("chmod sqlite db {path:?}: {e}"))?;
    for suffix in ["-wal", "-shm"] {
        let sibling = format!("{path}{suffix}");
        match std::fs::set_permissions(&sibling, perms.clone()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("chmod {sibling:?}: {e}")),
        }
    }
    Ok(())
}

/// Diesel's sqlite manager wants a filesystem path, not a URL. Accept both
/// `sqlite://./forseti.db` (config-friendly) and a bare `./forseti.db`
/// (operator-friendly) and produce a path.
fn sqlite_path(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("sqlite://") {
        rest.to_string()
    } else if let Some(rest) = url.strip_prefix("sqlite:") {
        rest.to_string()
    } else {
        url.to_string()
    }
}
