//! Never-reused id allocation backed by `posix_sequences`. A freed uid/gid is
//! NEVER reclaimed: a reused gid would silently reassign on-disk/backup file
//! ownership to a different team across hosts. Each band has its own row.

use diesel::prelude::*;

use crate::db::DbPool;
use crate::db_interact;
use crate::schema::posix_sequences;

/// Atomically take and advance the next id for `band` (`"uid"`, `"user_gid"`,
/// or `"team_gid"`). Initialises the row to `base` on first use. The returned
/// id is `>= base` and strictly greater than any previously returned id for the
/// band, regardless of row deletions elsewhere.
pub async fn next_in_band(db: &DbPool, band: &str, base: u32) -> anyhow::Result<u32> {
    let band = band.to_string();
    let val: i32 = db_interact!(db, |conn| {
        conn.transaction::<i32, diesel::result::Error, _>(|c| {
            // Write-first so SQLite takes the write lock up front (no
            // reader->writer upgrade) and Postgres serialises concurrent
            // bumps on the row lock.
            diesel::insert_into(posix_sequences::table)
                .values((
                    posix_sequences::name.eq(&band),
                    posix_sequences::next.eq(base as i32),
                ))
                .on_conflict(posix_sequences::name)
                .do_nothing()
                .execute(c)?;
            diesel::update(posix_sequences::table.filter(posix_sequences::name.eq(&band)))
                .set(posix_sequences::next.eq(posix_sequences::next + 1))
                .execute(c)?;
            let next: i32 = posix_sequences::table
                .filter(posix_sequences::name.eq(&band))
                .select(posix_sequences::next)
                .first(c)?;
            Ok(next - 1)
        })
    })?;
    Ok(val as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use uuid::Uuid;

    async fn temp_pool() -> DbPool {
        let path = std::env::temp_dir().join(format!("forseti-seq-{}.db", Uuid::new_v4()));
        let db = DbPool::init(&DatabaseConfig {
            url: format!("sqlite://{}", path.display()),
            skip_migrations: true,
        })
        .expect("pool");
        db.run_migrations().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn allocate_is_monotonic_and_never_reuses() {
        let db = temp_pool().await;
        let a = next_in_band(&db, "team_gid", 3_000_000).await.unwrap();
        let b = next_in_band(&db, "team_gid", 3_000_000).await.unwrap();
        assert_eq!(a, 3_000_000);
        assert_eq!(b, 3_000_001);
        // A different band starts at its own base independently.
        let u = next_in_band(&db, "uid", 1_000_000).await.unwrap();
        assert_eq!(u, 1_000_000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_allocations_never_duplicate() {
        let db = temp_pool().await;
        let mut handles = Vec::new();
        for _ in 0..32 {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                next_in_band(&db, "uid", 1_000_000).await.unwrap()
            }));
        }
        let mut ids = std::collections::HashSet::new();
        for h in handles {
            assert!(ids.insert(h.await.unwrap()), "duplicate id allocated");
        }
        assert_eq!(ids.len(), 32);
    }
}
