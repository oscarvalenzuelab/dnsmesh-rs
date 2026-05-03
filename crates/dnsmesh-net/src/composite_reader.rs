//! Composite reader: primary-with-fallback chaining.
//!
//! Tries a primary [`DnsRecordReader`] first; if it returns `Ok(None)` or
//! `Err(_)`, walks each fallback in declaration order and returns the first
//! `Ok(Some(...))` answer. Returns `Ok(None)` if every reader was a miss.
//!
//! Note on Python parity: `dmp/network/composite_reader.py` implements a
//! *routing* composite — it dispatches by owner-name suffix to either a
//! cluster reader or an external resolver, with NO fallback chaining. The
//! semantic chosen here ("try primary, then fall through") is the M2-polish
//! composition primitive called for by the Rust port plan; the suffix-router
//! is a higher-level concern that lives at the client layer (M9). Both
//! patterns are useful, but they're different compositions and only the
//! fallback-chain primitive belongs in this transport crate.
//!
//! Per-reader errors are logged at `warn` and treated as a miss so a flaky
//! primary can fall through to a healthier fallback rather than surfacing the
//! transport error to the caller.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use crate::base::DnsRecordReader;
use crate::error::NetError;

/// Primary-then-fallbacks reader composition.
pub struct CompositeReader {
    primary: Arc<dyn DnsRecordReader>,
    fallbacks: Vec<Arc<dyn DnsRecordReader>>,
}

impl CompositeReader {
    /// Construct a [`CompositeReader`] with a primary and zero or more
    /// fallbacks. Fallbacks are tried in the order supplied.
    #[must_use]
    pub fn new(
        primary: Arc<dyn DnsRecordReader>,
        fallbacks: Vec<Arc<dyn DnsRecordReader>>,
    ) -> Self {
        Self { primary, fallbacks }
    }

    /// Number of fallback readers (excludes the primary).
    #[must_use]
    pub fn fallback_count(&self) -> usize {
        self.fallbacks.len()
    }
}

#[async_trait]
impl DnsRecordReader for CompositeReader {
    async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError> {
        match self.primary.query_txt_record(name).await {
            Ok(Some(values)) => return Ok(Some(values)),
            Ok(None) => {}
            Err(err) => {
                warn!(error = %err, "composite reader: primary failed, trying fallbacks");
            }
        }
        for (idx, reader) in self.fallbacks.iter().enumerate() {
            match reader.query_txt_record(name).await {
                Ok(Some(values)) => return Ok(Some(values)),
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        index = idx,
                        error = %err,
                        "composite reader: fallback failed, trying next",
                    );
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::DnsRecordWriter;
    use crate::memory::InMemoryDnsStore;

    #[tokio::test]
    async fn primary_some_short_circuits() {
        let primary = Arc::new(InMemoryDnsStore::new());
        let fallback = Arc::new(InMemoryDnsStore::new());
        primary
            .publish_txt_record("alice.example.com", "primary-value", 300)
            .await
            .unwrap();
        fallback
            .publish_txt_record("alice.example.com", "fallback-value", 300)
            .await
            .unwrap();
        let reader = CompositeReader::new(
            primary as Arc<dyn DnsRecordReader>,
            vec![fallback as Arc<dyn DnsRecordReader>],
        );
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["primary-value".to_string()]);
    }

    #[tokio::test]
    async fn primary_none_falls_through_to_fallback() {
        let primary = Arc::new(InMemoryDnsStore::new());
        let fallback = Arc::new(InMemoryDnsStore::new());
        fallback
            .publish_txt_record("alice.example.com", "fallback-value", 300)
            .await
            .unwrap();
        let reader = CompositeReader::new(
            primary as Arc<dyn DnsRecordReader>,
            vec![fallback as Arc<dyn DnsRecordReader>],
        );
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["fallback-value".to_string()]);
    }

    #[tokio::test]
    async fn all_none_returns_none() {
        let primary = Arc::new(InMemoryDnsStore::new());
        let fallback_a = Arc::new(InMemoryDnsStore::new());
        let fallback_b = Arc::new(InMemoryDnsStore::new());
        let reader = CompositeReader::new(
            primary as Arc<dyn DnsRecordReader>,
            vec![
                fallback_a as Arc<dyn DnsRecordReader>,
                fallback_b as Arc<dyn DnsRecordReader>,
            ],
        );
        assert!(reader
            .query_txt_record("nope.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn fallbacks_are_tried_in_declaration_order() {
        let primary = Arc::new(InMemoryDnsStore::new());
        let fallback_a = Arc::new(InMemoryDnsStore::new());
        let fallback_b = Arc::new(InMemoryDnsStore::new());
        fallback_a
            .publish_txt_record("alice.example.com", "from-a", 300)
            .await
            .unwrap();
        fallback_b
            .publish_txt_record("alice.example.com", "from-b", 300)
            .await
            .unwrap();
        let reader = CompositeReader::new(
            primary as Arc<dyn DnsRecordReader>,
            vec![
                fallback_a as Arc<dyn DnsRecordReader>,
                fallback_b as Arc<dyn DnsRecordReader>,
            ],
        );
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["from-a".to_string()]);
    }

    /// Reader that always returns an error. Used to confirm primary errors
    /// fall through to fallbacks.
    struct AlwaysFailingReader;

    #[async_trait]
    impl DnsRecordReader for AlwaysFailingReader {
        async fn query_txt_record(&self, _name: &str) -> Result<Option<Vec<String>>, NetError> {
            Err(NetError::Transport("synthetic failure".into()))
        }
    }

    #[tokio::test]
    async fn primary_error_falls_through_to_fallback() {
        let fallback = Arc::new(InMemoryDnsStore::new());
        fallback
            .publish_txt_record("alice.example.com", "fallback-value", 300)
            .await
            .unwrap();
        let reader = CompositeReader::new(
            Arc::new(AlwaysFailingReader) as Arc<dyn DnsRecordReader>,
            vec![fallback as Arc<dyn DnsRecordReader>],
        );
        let got = reader
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["fallback-value".to_string()]);
    }
}
