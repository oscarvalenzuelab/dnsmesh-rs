//! Live integration test against the public DMP node `dmp.dnsmesh.io`.
//!
//! Marked `#[ignore]` so it doesn't run in `cargo test` by default — the
//! reference node may be down or rate-limiting at any given moment, which
//! shouldn't fail unrelated CI runs. Run explicitly with:
//!
//! ```sh
//! cargo test -p dnsmesh-net -- --ignored --nocapture
//! ```
//!
//! M2 gate: the test must read the live `_dnsmesh-heartbeat.dmp.dnsmesh.io`
//! TXT record through [`dnsmesh_net::ResolverPool`] and pass it through
//! [`dnsmesh_core::heartbeat::HeartbeatRecord::parse_and_verify`]. Together
//! that proves the Rust resolver + the Rust heartbeat parser interop with the
//! live Python node.

use dnsmesh_core::heartbeat::{HeartbeatRecord, RECORD_PREFIX};
use dnsmesh_net::{DnsRecordReader, ResolverPool};

const LIVE_HEARTBEAT_NAME: &str = "_dnsmesh-heartbeat.dmp.dnsmesh.io";

#[tokio::test]
#[ignore = "live network test; opt in with `cargo test -- --ignored`"]
async fn reads_live_dmp_dnsmesh_io_heartbeat() {
    let pool = ResolverPool::well_known().expect("well-known pool");

    let answers = pool
        .query_txt_record(LIVE_HEARTBEAT_NAME)
        .await
        .expect("resolver pool query")
        .expect("live node should publish a heartbeat record");

    assert!(!answers.is_empty(), "expected at least one TXT answer");

    let mut parsed_any = false;
    for answer in &answers {
        if !answer.starts_with(RECORD_PREFIX) {
            // The live RRset may carry unrelated TXT records; only inspect
            // ones with the heartbeat prefix.
            continue;
        }
        // Allow some clock skew tolerance against live records that may have
        // been published a few minutes ago.
        match HeartbeatRecord::parse_and_verify(answer, None, 600) {
            Some(record) => {
                println!(
                    "live heartbeat ok: endpoint={:?} version={:?} ts={} exp={}",
                    record.endpoint, record.version, record.ts, record.exp
                );
                parsed_any = true;
            }
            None => {
                panic!("wire-prefix matched but parse_and_verify returned None: {answer}");
            }
        }
    }
    assert!(
        parsed_any,
        "no TXT answer started with {RECORD_PREFIX:?}; got {answers:?}"
    );
}
