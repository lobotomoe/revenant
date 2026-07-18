//! Fetching and time-to-live caching of parsed trust stores.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::{parse_tsl, TrustStore};
use crate::constants::{DEFAULT_MAX_RETRIES, TSL_FETCH_TIMEOUT};
use crate::net::Transport;
use crate::Result;

/// Fetch a TSL over HTTPS and parse it.
///
/// # Errors
///
/// Returns a [`crate::RevenantError`] on network or parse failure.
pub fn fetch_trust_store(
    transport: &Transport,
    tsl_url: &str,
    timeout: Duration,
) -> Result<TrustStore> {
    log::info!("Fetching TSL from {tsl_url}");
    let xml = transport.get(tsl_url, timeout, DEFAULT_MAX_RETRIES)?;
    parse_tsl(&xml, tsl_url)
}

/// A time-to-live cache of parsed trust stores, keyed by TSL URL.
///
/// A single instance is owned by the caller (the API layer) and shared; it is
/// `Send + Sync`.
#[derive(Debug, Default)]
pub struct TrustStoreCache {
    cache: Mutex<HashMap<String, TrustStore>>,
}

impl TrustStoreCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a cached store if fresh, otherwise fetch and cache it. On fetch
    /// failure, fall back to a stale cached entry if one exists (else `None`).
    /// Never raises -- a missing trust store degrades chain validation to
    /// "indeterminate", it does not abort it.
    pub fn get_or_fetch(
        &self,
        transport: &Transport,
        tsl_url: &str,
        ttl: Duration,
    ) -> Option<TrustStore> {
        self.get_or_fetch_with(tsl_url, ttl, || {
            fetch_trust_store(transport, tsl_url, TSL_FETCH_TIMEOUT)
        })
    }

    /// Empty the cache.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Core cache logic with an injectable fetch, so every path is unit-tested
    /// without a live transport.
    fn get_or_fetch_with(
        &self,
        tsl_url: &str,
        ttl: Duration,
        fetch: impl FnOnce() -> Result<TrustStore>,
    ) -> Option<TrustStore> {
        if let Some(fresh) = self.fresh_cached(tsl_url, ttl) {
            return Some(fresh);
        }
        match fetch() {
            Ok(store) => {
                self.lock().insert(tsl_url.to_owned(), store.clone());
                Some(store)
            }
            Err(err) => {
                log::warn!("Failed to fetch TSL from {tsl_url}: {err}");
                self.lock().get(tsl_url).cloned() // stale, if present
            }
        }
    }

    /// A cached store for `tsl_url`, but only if younger than `ttl`.
    fn fresh_cached(&self, tsl_url: &str, ttl: Duration) -> Option<TrustStore> {
        let cache = self.lock();
        let cached = cache.get(tsl_url)?;
        (cached.fetched_at.elapsed() < ttl).then(|| cached.clone())
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, TrustStore>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RevenantError;
    use std::time::Instant;

    fn make_store(operator: &str) -> TrustStore {
        TrustStore {
            anchors: Vec::new(),
            ca_anchors: Vec::new(),
            scheme_operator: operator.to_owned(),
            tsl_url: "https://example.com/tsl.xml".to_owned(),
            fetched_at: Instant::now(),
        }
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn returns_fresh_entry_without_fetching() {
        let cache = TrustStoreCache::new();
        cache.lock().insert("url".to_owned(), make_store("Cached"));
        let result =
            cache.get_or_fetch_with("url", HOUR, || panic!("must not fetch on a fresh hit"));
        assert_eq!(result.unwrap().scheme_operator, "Cached");
    }

    #[test]
    fn stores_fetched_result() {
        let cache = TrustStoreCache::new();
        let result = cache.get_or_fetch_with("url", HOUR, || Ok(make_store("Fresh")));
        assert_eq!(result.unwrap().scheme_operator, "Fresh");
        assert!(cache.fresh_cached("url", HOUR).is_some());
    }

    #[test]
    fn returns_none_on_fetch_failure_with_no_entry() {
        let cache = TrustStoreCache::new();
        let result = cache.get_or_fetch_with("url", HOUR, || {
            Err(RevenantError::Other("network".to_owned()))
        });
        assert!(result.is_none());
    }

    #[test]
    fn returns_stale_on_fetch_failure() {
        let cache = TrustStoreCache::new();
        cache.lock().insert("url".to_owned(), make_store("Stale"));
        // ttl = 0 forces the entry to be treated as stale.
        let result = cache.get_or_fetch_with("url", Duration::ZERO, || {
            Err(RevenantError::Other("down".to_owned()))
        });
        assert_eq!(result.unwrap().scheme_operator, "Stale");
    }

    #[test]
    fn clear_empties() {
        let cache = TrustStoreCache::new();
        cache.lock().insert("url".to_owned(), make_store("X"));
        cache.clear();
        assert!(cache.fresh_cached("url", HOUR).is_none());
    }
}
