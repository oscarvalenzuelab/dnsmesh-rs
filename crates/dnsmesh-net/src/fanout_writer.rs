//! Fanout writer: dispatch publishes/deletes across multiple authoritative
//! backends and collapse the per-target outcomes via a quorum policy.
//!
//! Mirrors the M2 client surface of `dmp/network/fanout_writer.py` — the
//! composition-layer slice. The Python implementation also carries
//! `ClusterManifest`-driven lifecycle (seq monotonicity, retired executors
//! across refreshes, per-node health snapshots, in-flight retention lists);
//! those concerns are M9 territory and are deliberately omitted here. For M2
//! we only need the write-side composition primitive: fan to N writers in
//! parallel, swallow per-target errors, and decide success via a small
//! [`Quorum`] policy.
//!
//! Quorum policy
//! -------------
//! The Python writer hard-codes `ceil(N/2)` ("majority") because it is
//! coupled to a `ClusterManifest`. The Rust port is a generic composition
//! primitive, so the threshold is supplied by the caller via [`Quorum`]. The
//! supported policies cover the cases encountered in practice:
//!
//! - [`Quorum::All`] — every writer must acknowledge. Strictest; matches a
//!   primary/secondary mirror that wants both copies to land before
//!   declaring success.
//! - [`Quorum::Any`] — at least one writer must acknowledge. Weakest;
//!   matches a "best-effort with replicas" pattern where any single landing
//!   counts as durability.
//! - `Quorum::AtLeast(n)` — at least `n` writers must acknowledge. Use
//!   `AtLeast(ceil(N/2))` to model the Python `FanoutWriter` majority rule.
//!   `n == 0` is allowed and trivially satisfied; `n > N` is unsatisfiable
//!   and will always return `Ok(false)`.
//!
//! Per-target failures (returned `Ok(false)` or surfaced `Err(_)`) are logged
//! at `warn` and counted as misses for the quorum tally; the call as a whole
//! succeeds iff the policy is satisfied. The fanout never bubbles up a
//! per-writer transport error to the caller.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::join_all;
use tracing::warn;

use crate::base::DnsRecordWriter;
use crate::error::NetError;

/// Quorum policy applied to the per-target acknowledgement count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    /// Every writer must acknowledge.
    All,
    /// At least one writer must acknowledge.
    Any,
    /// At least `n` writers must acknowledge. `n == 0` is always satisfied;
    /// `n` greater than the writer count is never satisfied.
    AtLeast(usize),
}

impl Quorum {
    /// Resolve the policy against the population size and number of acks.
    fn satisfied(self, total: usize, acks: usize) -> bool {
        match self {
            Self::All => acks == total,
            Self::Any => acks >= 1,
            Self::AtLeast(n) => acks >= n,
        }
    }
}

/// Fans publishes/deletes across multiple [`DnsRecordWriter`] backends and
/// collapses the per-target outcomes via a [`Quorum`] policy.
pub struct FanoutWriter {
    writers: Vec<Arc<dyn DnsRecordWriter>>,
    quorum: Quorum,
}

impl FanoutWriter {
    /// Construct a [`FanoutWriter`] over the supplied backend writers and
    /// quorum policy.
    ///
    /// An empty writer list is permitted but degenerate: [`Quorum::All`] is
    /// vacuously satisfied, [`Quorum::Any`] is unsatisfiable (no acks
    /// possible), and `Quorum::AtLeast(n)` is satisfied iff `n == 0`.
    #[must_use]
    pub fn new(writers: Vec<Arc<dyn DnsRecordWriter>>, quorum: Quorum) -> Self {
        Self { writers, quorum }
    }

    /// Number of backend writers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.writers.len()
    }

    /// True iff no backend writers were configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writers.is_empty()
    }

    /// Currently active quorum policy.
    #[must_use]
    pub fn quorum(&self) -> Quorum {
        self.quorum
    }

    /// Tally per-target outcomes: count successful (`Ok(true)`) responses,
    /// log every failure, and return whether the quorum policy holds.
    fn tally(&self, op: &'static str, results: Vec<Result<bool, NetError>>) -> bool {
        let total = results.len();
        let mut acks: usize = 0;
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(true) => acks += 1,
                Ok(false) => {
                    warn!(target_index = idx, op, "fanout writer: target rejected");
                }
                Err(err) => {
                    warn!(
                        target_index = idx,
                        op,
                        error = %err,
                        "fanout writer: target errored",
                    );
                }
            }
        }
        self.quorum.satisfied(total, acks)
    }
}

#[async_trait]
impl DnsRecordWriter for FanoutWriter {
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError> {
        let futures = self
            .writers
            .iter()
            .map(|w| {
                let w = Arc::clone(w);
                let name = name.to_string();
                let value = value.to_string();
                async move { w.publish_txt_record(&name, &value, ttl_seconds).await }
            })
            .collect::<Vec<_>>();
        let results = join_all(futures).await;
        Ok(self.tally("publish", results))
    }

    async fn delete_txt_record(&self, name: &str, value: Option<&str>) -> Result<bool, NetError> {
        let futures = self
            .writers
            .iter()
            .map(|w| {
                let w = Arc::clone(w);
                let name = name.to_string();
                let value = value.map(str::to_string);
                async move { w.delete_txt_record(&name, value.as_deref()).await }
            })
            .collect::<Vec<_>>();
        let results = join_all(futures).await;
        Ok(self.tally("delete", results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::DnsRecordReader;
    use crate::memory::InMemoryDnsStore;

    /// Writer that always returns `Ok(false)`. Used to exercise quorum
    /// shortfall paths without relying on a real backend.
    struct AlwaysFalseWriter;

    #[async_trait]
    impl DnsRecordWriter for AlwaysFalseWriter {
        async fn publish_txt_record(
            &self,
            _name: &str,
            _value: &str,
            _ttl_seconds: u32,
        ) -> Result<bool, NetError> {
            Ok(false)
        }
        async fn delete_txt_record(
            &self,
            _name: &str,
            _value: Option<&str>,
        ) -> Result<bool, NetError> {
            Ok(false)
        }
    }

    /// Writer that always returns a transport error. Used to exercise the
    /// "errors count as misses" path.
    struct AlwaysErrWriter;

    #[async_trait]
    impl DnsRecordWriter for AlwaysErrWriter {
        async fn publish_txt_record(
            &self,
            _name: &str,
            _value: &str,
            _ttl_seconds: u32,
        ) -> Result<bool, NetError> {
            Err(NetError::Transport("synthetic publish failure".into()))
        }
        async fn delete_txt_record(
            &self,
            _name: &str,
            _value: Option<&str>,
        ) -> Result<bool, NetError> {
            Err(NetError::Transport("synthetic delete failure".into()))
        }
    }

    #[tokio::test]
    async fn quorum_all_with_all_writers_succeeding_publishes_to_each() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(
            vec![
                Arc::clone(&store_a) as Arc<dyn DnsRecordWriter>,
                Arc::clone(&store_b) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::All,
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(
            store_a
                .query_txt_record("alice.example.com")
                .await
                .unwrap()
                .unwrap(),
            vec!["v=dmp1".to_string()],
        );
        assert_eq!(
            store_b
                .query_txt_record("alice.example.com")
                .await
                .unwrap()
                .unwrap(),
            vec!["v=dmp1".to_string()],
        );
    }

    #[tokio::test]
    async fn quorum_all_with_one_writer_failing_returns_false() {
        let store = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(
            vec![
                store as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::All,
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn quorum_any_with_one_succeeding_returns_true() {
        let store = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(
            vec![
                Arc::clone(&store) as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::Any,
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(
            store
                .query_txt_record("alice.example.com")
                .await
                .unwrap()
                .unwrap(),
            vec!["v=dmp1".to_string()],
        );
    }

    #[tokio::test]
    async fn quorum_any_with_all_failing_returns_false() {
        let writer = FanoutWriter::new(
            vec![
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::Any,
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn quorum_at_least_threshold_is_respected() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(
            vec![
                store_a as Arc<dyn DnsRecordWriter>,
                store_b as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::AtLeast(2),
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn quorum_at_least_unsatisfiable_returns_false() {
        let store = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(vec![store as Arc<dyn DnsRecordWriter>], Quorum::AtLeast(2));
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn errors_are_counted_as_misses() {
        let store = Arc::new(InMemoryDnsStore::new());
        let writer = FanoutWriter::new(
            vec![
                store as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysErrWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::All,
        );
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn delete_fans_out_with_quorum_all() {
        let store_a = Arc::new(InMemoryDnsStore::new());
        let store_b = Arc::new(InMemoryDnsStore::new());
        store_a
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        store_b
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        let writer = FanoutWriter::new(
            vec![
                Arc::clone(&store_a) as Arc<dyn DnsRecordWriter>,
                Arc::clone(&store_b) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::All,
        );
        let ok = writer
            .delete_txt_record("alice.example.com", Some("v=dmp1"))
            .await
            .unwrap();
        assert!(ok);
        assert!(store_a
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .is_none());
        assert!(store_b
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn delete_with_quorum_any_succeeds_when_one_target_succeeds() {
        let store = Arc::new(InMemoryDnsStore::new());
        store
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        let writer = FanoutWriter::new(
            vec![
                Arc::clone(&store) as Arc<dyn DnsRecordWriter>,
                Arc::new(AlwaysFalseWriter) as Arc<dyn DnsRecordWriter>,
            ],
            Quorum::Any,
        );
        let ok = writer
            .delete_txt_record("alice.example.com", Some("v=dmp1"))
            .await
            .unwrap();
        assert!(ok);
        assert!(store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn empty_writer_list_with_quorum_all_is_vacuously_true() {
        let writer = FanoutWriter::new(Vec::new(), Quorum::All);
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn empty_writer_list_with_quorum_any_is_false() {
        let writer = FanoutWriter::new(Vec::new(), Quorum::Any);
        let ok = writer
            .publish_txt_record("alice.example.com", "v=dmp1", 300)
            .await
            .unwrap();
        assert!(!ok);
    }
}
