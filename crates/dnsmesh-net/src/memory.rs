//! In-memory DNS store for tests and local development.
//!
//! Mirrors `dmp/network/memory.py` for the client-side surface (publish, delete,
//! query). The Python store also exposes anti-entropy helpers
//! (`iter_records_since`, `get_records_by_name`) used by the server's replication
//! worker — those stay in Python and are out of scope for this crate.
//!
//! Not suitable for anything that leaves a single process. Writes are instantly
//! visible to reads.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::base::{DnsRecordReader, DnsRecordWriter};
use crate::error::NetError;

#[derive(Debug, Clone)]
struct Entry {
    value: String,
    expires_at_secs: u64,
}

/// Dict-backed DNS store. Thread-safe; all operations grab a single mutex.
#[derive(Debug, Default)]
pub struct InMemoryDnsStore {
    records: Mutex<HashMap<String, Vec<Entry>>>,
}

impl InMemoryDnsStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience for tests: list every name that currently has at least one
    /// non-expired entry, sorted lexicographically.
    #[must_use]
    pub fn list_names(&self) -> Vec<String> {
        let now = current_unix_secs();
        let guard = self.records.lock();
        let mut out: Vec<String> = guard
            .iter()
            .filter(|(_, entries)| entries.iter().any(|e| e.expires_at_secs > now))
            .map(|(k, _)| k.clone())
            .collect();
        out.sort();
        out
    }

    /// Drop every record. For test isolation.
    pub fn clear(&self) {
        self.records.lock().clear();
    }
}

#[async_trait]
impl DnsRecordWriter for InMemoryDnsStore {
    async fn publish_txt_record(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<bool, NetError> {
        // DNS allows multiple TXT records at one name (an RRset). A publish at an
        // already-occupied name ADDS to the set rather than replacing it, so an
        // attacker who reaches the publish endpoint can add records but cannot
        // evict legitimate ones. Identical re-publishes are idempotent.
        let now = current_unix_secs();
        let expires = now.saturating_add(u64::from(ttl_seconds));
        let mut guard = self.records.lock();
        let entries = guard.entry(name.to_string()).or_default();
        for entry in entries.iter_mut() {
            if entry.value == value {
                entry.expires_at_secs = expires;
                return Ok(true);
            }
        }
        entries.push(Entry {
            value: value.to_string(),
            expires_at_secs: expires,
        });
        Ok(true)
    }

    async fn delete_txt_record(&self, name: &str, value: Option<&str>) -> Result<bool, NetError> {
        let mut guard = self.records.lock();
        let Some(entries) = guard.get_mut(name) else {
            return Ok(false);
        };
        match value {
            None => {
                guard.remove(name);
                Ok(true)
            }
            Some(v) => {
                let before = entries.len();
                entries.retain(|e| e.value != v);
                let removed = entries.len() != before;
                if entries.is_empty() {
                    guard.remove(name);
                }
                Ok(removed)
            }
        }
    }
}

#[async_trait]
impl DnsRecordReader for InMemoryDnsStore {
    async fn query_txt_record(&self, name: &str) -> Result<Option<Vec<String>>, NetError> {
        let now = current_unix_secs();
        let guard = self.records.lock();
        let Some(entries) = guard.get(name) else {
            return Ok(None);
        };
        let live: Vec<String> = entries
            .iter()
            .filter(|e| e.expires_at_secs > now)
            .map(|e| e.value.clone())
            .collect();
        if live.is_empty() {
            Ok(None)
        } else {
            Ok(Some(live))
        }
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_then_query_round_trips() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alice.example.com", "v=dmp1;t=identity;d=...", 300)
            .await
            .unwrap();
        let got = store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["v=dmp1;t=identity;d=...".to_string()]);
    }

    #[tokio::test]
    async fn missing_name_returns_none() {
        let store = InMemoryDnsStore::new();
        assert!(store.query_txt_record("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rrset_supports_multiple_values() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alice.example.com", "value-1", 300)
            .await
            .unwrap();
        store
            .publish_txt_record("alice.example.com", "value-2", 300)
            .await
            .unwrap();
        let mut got = store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        got.sort();
        assert_eq!(got, vec!["value-1".to_string(), "value-2".to_string()]);
    }

    #[tokio::test]
    async fn duplicate_publish_is_idempotent() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alice.example.com", "v", 300)
            .await
            .unwrap();
        store
            .publish_txt_record("alice.example.com", "v", 600)
            .await
            .unwrap();
        let got = store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn delete_by_name_removes_all() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alice.example.com", "value-1", 300)
            .await
            .unwrap();
        store
            .publish_txt_record("alice.example.com", "value-2", 300)
            .await
            .unwrap();
        assert!(store
            .delete_txt_record("alice.example.com", None)
            .await
            .unwrap());
        assert!(store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn delete_by_value_targets_exact_rrset_member() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alice.example.com", "value-1", 300)
            .await
            .unwrap();
        store
            .publish_txt_record("alice.example.com", "value-2", 300)
            .await
            .unwrap();
        assert!(store
            .delete_txt_record("alice.example.com", Some("value-1"))
            .await
            .unwrap());
        let got = store
            .query_txt_record("alice.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, vec!["value-2".to_string()]);
    }

    #[tokio::test]
    async fn list_names_filters_expired() {
        let store = InMemoryDnsStore::new();
        store
            .publish_txt_record("alive.example.com", "v", 600)
            .await
            .unwrap();
        store
            .publish_txt_record("dying.example.com", "v", 0)
            .await
            .unwrap();
        let names = store.list_names();
        assert!(names.contains(&"alive.example.com".to_string()));
        assert!(!names.contains(&"dying.example.com".to_string()));
    }
}
