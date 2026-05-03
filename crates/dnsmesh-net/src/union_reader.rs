//! Union reader: fan a TXT query across every backend in parallel.
//!
//! Mirrors `dmp/network/union_reader.py` for the M2 client surface — the
//! composition-layer slice. Unlike the Python implementation, this Rust port
//! does NOT carry the `ClusterManifest` lifecycle (seq monotonicity, retired
//! executors, per-node health snapshots, in-flight retention lists). Manifest
//! refresh is M9 territory; for M2 we only need the read-side composition
//! semantics: fan to N readers, union the answers, swallow per-reader errors.
//!
//! Semantics
//! ---------
//! - Queries fan to every underlying reader in parallel via
//!   [`futures_util::future::join_all`].
//! - Each reader contributes any non-empty `Some(values)` to the union.
//! - Identical TXT strings are deduplicated; first-completed-first wins for
//!   ordering.
//! - A reader that returns `Ok(None)` contributes nothing but is healthy.
//! - A reader that returns `Err(_)` contributes nothing and is logged at
//!   `warn` — a single failing backend never poisons the union.
//! - Returns `Ok(None)` iff every reader returned `Ok(None)` or `Err(_)`.
//! - Empty backend list → always `Ok(None)`.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::join_all;
use tracing::warn;

use crate::base::DnsRecordReader;
use crate::error::NetError;

/// Fans TXT queries across multiple [`DnsRecordReader`] backends and unions the
/// results.
///
/// See module-level documentation for the failure semantics.
pub struct UnionReader {
    readers: Vec<Arc<dyn DnsRecordReader>>,
}

impl UnionReader {
    /// Construct a [`UnionReader`] over the supplied backend readers.
    ///
    /// An empty list is permitted; every query against it returns `Ok(None)`.
    /// Constructing one is occasionally useful for tests and as a no-op
    /// fallback in composition trees.
    #[must_use]
    pub fn new(readers: Vec<Arc<dyn DnsRecordReader>>) -> Self {
        Self { readers }
    }

    /// Number of backend readers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.readers.len()
    }

    /// True iff no backend readers were configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.readers.is_empty()
    }
}

#[async_trait]
impl DnsRecordReader for UnionReader {
    async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError> {
        if self.readers.is_empty() {
            return Ok(None);
        }
        let futures = self
            .readers
            .iter()
            .map(|r| {
                let r = Arc::clone(r);
                let name = name.to_string();
                async move { r.query_txt_record(&name).await }
            })
            .collect::<Vec<_>>();
        let results = join_all(futures).await;

        // Insertion-ordered dedup: first completion wins position. We can't
        // strictly preserve completion order with `join_all` (it returns in
        // submission order), but the union is order-insensitive at the
        // contract level — callers that need stable ordering must sort.
        let mut union: Vec<String> = Vec::new();
        for result in results {
            match result {
                Ok(Some(values)) => {
                    for value in values {
                        if !union.contains(&value) {
                            union.push(value);
                        }
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    // Log and swallow: a single failing backend must not
                    // poison the union.
                    warn!(error = %err, "union reader: backend query failed");
                }
            }
        }
        if union.is_empty() {
            Ok(None)
        } else {
            Ok(Some(union))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::DnsRecordWriter;
    use crate::memory::InMemoryDnsStore;

    #[tokio::test]
    async fn empty_backend_list_returns_none() {
        let reader = UnionReader::new(Vec::new());
        assert!(reader.query_txt_record("anything").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn single_backend_with_record_returns_its_values() {
        let store = Arc::new(InMemoryDnsStore::new());
        store
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        let reader = UnionReader::new(vec![store as Arc<dyn DnsRecordReader>]);
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["v=dmp1".to_string()]);
    }

    #[tokio::test]
    async fn missing_in_all_backends_returns_none() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        let reader = UnionReader::new(vec![
            store_a as Arc<dyn DnsRecordReader>,
            store_b as Arc<dyn DnsRecordReader>,
        ]);
        assert!(reader
            .query_txt_record("nope.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn one_backend_has_record_other_does_not() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        store_a
            .publish_txt_record("alice.example.com", "only-in-a", 300)
            .await
            .unwrap();
        let reader = UnionReader::new(vec![
            store_a as Arc<dyn DnsRecordReader>,
            store_b as Arc<dyn DnsRecordReader>,
        ]);
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["only-in-a".to_string()]);
    }

    #[tokio::test]
    async fn duplicate_values_across_backends_are_deduplicated() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        store_a
            .publish_txt_record("alice.example.com", "shared", 300)
            .await
            .unwrap();
        store_b
            .publish_txt_record("alice.example.com", "shared", 300)
            .await
            .unwrap();
        let reader = UnionReader::new(vec![
            store_a as Arc<dyn DnsRecordReader>,
            store_b as Arc<dyn DnsRecordReader>,
        ]);
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["shared".to_string()]);
    }

    #[tokio::test]
    async fn distinct_values_across_backends_are_unioned() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        store_a
            .publish_txt_record("alice.example.com", "value-a", 300)
            .await
            .unwrap();
        store_b
            .publish_txt_record("alice.example.com", "value-b", 300)
            .await
            .unwrap();
        let reader = UnionReader::new(vec![
            store_a as Arc<dyn DnsRecordReader>,
            store_b as Arc<dyn DnsRecordReader>,
        ]);
        let mut got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        got.sort();
        assert_eq!(got, vec!["value-a".to_string(), "value-b".to_string()]);
    }

    /// Reader that always returns an error. Used to confirm that backend
    /// errors are swallowed rather than poisoning the union.
    struct AlwaysFailingReader;

    #[async_trait]
    impl DnsRecordReader for AlwaysFailingReader {
        async fn query_txt_record(&self, _name: &str) -> Result<Option<Vec<String>>, NetError> {
            Err(NetError::Transport("synthetic failure".into()))
        }
    }

    #[tokio::test]
    async fn failing_backend_does_not_poison_union() {
        let healthy = Arc::new(InMemoryDnsStore::new());
        healthy
            .publish_txt_record("alice.example.com", "healthy-value", 300)
            .await
            .unwrap();
        let reader = UnionReader::new(vec![
            Arc::new(AlwaysFailingReader) as Arc<dyn DnsRecordReader>,
            healthy as Arc<dyn DnsRecordReader>,
        ]);
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["healthy-value".to_string()]);
    }
}
