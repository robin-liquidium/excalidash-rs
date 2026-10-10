//! server/drawingsCache.ts — bounded LRU cache of serialized drawing-list responses.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

struct Entry {
    body: bytes::Bytes,
    expires_at: Instant,
    user_id: String,
}

pub struct DrawingsCache {
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    max_body_bytes: usize,
    // insertion-ordered (front = least recently used)
    inner: Mutex<(Vec<(String, Entry)>, usize)>,
}

pub struct CacheKeyParts<'a> {
    pub user_id: &'a str,
    pub search_term: &'a str,
    pub collection_filter: &'a str,
    pub include_data: bool,
    pub sort_field: &'a str,
    pub sort_direction: &'a str,
}

impl DrawingsCache {
    pub fn new(ttl_ms: u64) -> Self {
        DrawingsCache {
            ttl: Duration::from_millis(ttl_ms),
            max_entries: 500,
            max_bytes: 64 * 1024 * 1024,
            max_body_bytes: 4 * 1024 * 1024,
            inner: Mutex::new((Vec::new(), 0)),
        }
    }

    pub fn build_key(p: &CacheKeyParts<'_>) -> String {
        serde_json::to_string(&[
            p.user_id,
            p.search_term,
            p.collection_filter,
            if p.include_data { "full" } else { "summary" },
            p.sort_field,
            p.sort_direction,
        ])
        .unwrap()
    }

    pub fn get(&self, key: &str) -> Option<bytes::Bytes> {
        let mut g = self.inner.lock().unwrap();
        let (list, total) = &mut *g;
        let idx = list.iter().position(|(k, _)| k == key)?;
        if Instant::now() > list[idx].1.expires_at {
            let (_, e) = list.remove(idx);
            *total -= e.body.len();
            return None;
        }
        let item = list.remove(idx);
        let body = item.1.body.clone();
        list.push(item);
        Some(body)
    }

    pub fn put(&self, key: &str, body: bytes::Bytes, user_id: &str) {
        let mut g = self.inner.lock().unwrap();
        let (list, total) = &mut *g;
        if let Some(idx) = list.iter().position(|(k, _)| k == key) {
            let (_, e) = list.remove(idx);
            *total -= e.body.len();
        }
        if body.len() > self.max_body_bytes {
            return;
        }
        *total += body.len();
        list.push((
            key.to_string(),
            Entry { body, expires_at: Instant::now() + self.ttl, user_id: user_id.to_string() },
        ));
        while list.len() > self.max_entries || (*total > self.max_bytes && !list.is_empty()) {
            let (_, e) = list.remove(0);
            *total -= e.body.len();
        }
    }

    /// `invalidateDrawingsCache(userId?)`
    pub fn invalidate(&self, user_id: Option<&str>) {
        let mut g = self.inner.lock().unwrap();
        let (list, total) = &mut *g;
        match user_id {
            None => {
                list.clear();
                *total = 0;
            }
            Some(uid) => {
                list.retain(|(_, e)| {
                    if e.user_id == uid {
                        *total -= e.body.len();
                        false
                    } else {
                        true
                    }
                });
            }
        }
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let (list, total) = &mut *g;
        list.retain(|(_, e)| {
            if now > e.expires_at {
                *total -= e.body.len();
                false
            } else {
                true
            }
        });
    }
}
