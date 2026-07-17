//! Bounded in-process cache for org logo blobs, keyed by org id.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use axum::body::Bytes;

pub(crate) const DEFAULT_MAX_ENTRIES: usize = 200;
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct CachedLogo {
    pub(crate) etag: String,
    pub(crate) content_type: String,
    pub(crate) bytes: Bytes,
}

pub(crate) struct LogoCache {
    entries: HashMap<String, Arc<CachedLogo>>,
    order: VecDeque<String>,
    total_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
}

impl LogoCache {
    pub(crate) fn new(max_entries: usize, max_total_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            max_entries,
            max_total_bytes,
        }
    }

    pub(crate) fn get(&self, org_id: &str) -> Option<Arc<CachedLogo>> {
        self.entries.get(org_id).cloned()
    }

    pub(crate) fn insert(&mut self, org_id: String, logo: Arc<CachedLogo>) {
        self.remove(&org_id);
        self.total_bytes += logo.bytes.len();
        self.order.push_back(org_id.clone());
        self.entries.insert(org_id, logo);

        // `> 1` keeps a lone oversized entry rather than evicting the item just inserted.
        while self.entries.len() > 1
            && (self.entries.len() > self.max_entries || self.total_bytes > self.max_total_bytes)
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.remove(&oldest);
        }
    }

    pub(crate) fn remove(&mut self, org_id: &str) {
        if let Some(evicted) = self.entries.remove(org_id) {
            self.total_bytes -= evicted.bytes.len();
            self.order.retain(|k| k != org_id);
        }
    }
}

impl Default for LogoCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_TOTAL_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logo(bytes: usize) -> Arc<CachedLogo> {
        Arc::new(CachedLogo {
            etag: "\"e\"".to_string(),
            content_type: "image/png".to_string(),
            bytes: Bytes::from(vec![0u8; bytes]),
        })
    }

    #[test]
    fn get_hits_after_insert() {
        let mut cache = LogoCache::new(10, 10_000);
        cache.insert("o1".to_string(), logo(4));
        let hit = cache.get("o1").expect("cache hit");
        assert_eq!(hit.bytes.len(), 4);
    }

    #[test]
    fn get_misses_unknown_key() {
        let cache = LogoCache::new(10, 10_000);
        assert!(cache.get("nope").is_none());
    }

    #[test]
    fn entry_count_ceiling_evicts_oldest() {
        let mut cache = LogoCache::new(2, 10_000);
        cache.insert("o1".to_string(), logo(4));
        cache.insert("o2".to_string(), logo(4));
        cache.insert("o3".to_string(), logo(4));

        assert!(cache.get("o1").is_none());
        assert!(cache.get("o2").is_some());
        assert!(cache.get("o3").is_some());
    }

    #[test]
    fn total_byte_ceiling_evicts_oldest() {
        let mut cache = LogoCache::new(10, 100);
        cache.insert("o1".to_string(), logo(60));
        cache.insert("o2".to_string(), logo(60));

        assert!(cache.get("o1").is_none());
        assert!(cache.get("o2").is_some());
    }

    #[test]
    fn reinsert_same_key_replaces_without_double_counting_bytes() {
        let mut cache = LogoCache::new(10, 100);
        cache.insert("o1".to_string(), logo(60));
        cache.insert("o1".to_string(), logo(60));
        cache.insert("o2".to_string(), logo(30));

        assert!(cache.get("o1").is_some());
        assert!(cache.get("o2").is_some());
    }

    #[test]
    fn oversized_single_entry_is_kept_alone() {
        let mut cache = LogoCache::new(10, 10);
        cache.insert("o1".to_string(), logo(1_000));
        assert!(cache.get("o1").is_some());
    }
}
