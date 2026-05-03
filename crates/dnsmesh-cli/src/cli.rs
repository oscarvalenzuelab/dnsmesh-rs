//! Clap-derive types for the `dnsmesh` CLI surface.
//!
//! The subcommand surface here is the M4 minimum gate from the build
//! plan: init / identity (show, publish, refresh-prekeys, fetch) /
//! contacts (add, list) / send / recv / doctor. M8 adds intro
//! (list, accept, trust, block); cluster + register stay out of
//! scope until later milestones.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};

/// `dnsmesh` — DMP command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "dnsmesh",
    version,
    about = "DMP — DNS Mesh Protocol command-line interface",
    long_about = None,
)]
pub struct Args {
    /// Path to a YAML config file (defaults to $DMP_CONFIG_HOME/config.yaml or ~/.dmp/config.yaml).
    #[arg(long, global = true, value_name = "PATH", env = "DMP_CONFIG")]
    pub config: Option<PathBuf>,

    /// Read the passphrase from the named env var instead of prompting.
    /// Use only for non-interactive scripts and CI; the value will be
    /// visible to anything that can read your process environment.
    #[arg(
        long,
        global = true,
        value_name = "ENV_VAR",
        env = "DMP_INSECURE_PASSPHRASE_ENV"
    )]
    pub insecure_passphrase_env: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new identity (writes ~/.dmp/config.yaml + sqlite db).
    Init(InitArgs),

    /// Identity management (show, publish, refresh-prekeys, fetch).
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Local address book.
    #[command(subcommand)]
    Contacts(ContactsCmd),

    /// Quarantine queue for first-contact messages from un-pinned senders.
    #[command(subcommand)]
    Intro(IntroCmd),

    /// Register for a per-user publish token on a multi-tenant node.
    /// The token authenticates HTTPS publishes to the node's API
    /// endpoint. For RFC 2136 TSIG-based publishes use `tsig register`.
    Register(RegisterArgs),

    /// DNS UPDATE TSIG-key registration / management.
    #[command(subcommand)]
    Tsig(TsigCmd),

    /// Send an end-to-end-encrypted message. sendmail-compat with `-t`.
    Send(SendArgs),

    /// Poll mailbox slots and emit decrypted messages (Maildir delivery with `--maildir`).
    Recv(RecvArgs),

    /// Light diagnostics over config / database / DNS reachability.
    Doctor,

    /// Wipe local state and (with --remote) walk DNS UPDATE deletes
    /// against every record this identity published. Use this when
    /// you want to fully decommission an identity instead of just
    /// `rm ~/.dmp` and waiting for DNS TTLs.
    Purge(PurgeArgs),
}

/// Common args for `register` and `tsig register`.
#[derive(Debug, ClapArgs)]
pub struct RegisterArgs {
    /// Node hostname (e.g. `dnsmesh.io`). Bare host or full URL —
    /// the scheme + path are stripped.
    #[arg(long, value_name = "HOST")]
    pub node: String,

    /// Subject to register; defaults to `<username>@<domain>` from
    /// the local config.
    #[arg(long)]
    pub subject: Option<String>,

    /// URL scheme for the registration call. Always `https` outside
    /// of dev runs against a node listening on plain HTTP.
    #[arg(long, default_value = "https")]
    pub scheme: String,
}

#[derive(Debug, Subcommand)]
pub enum TsigCmd {
    /// Register a TSIG key on a multi-tenant node and persist it
    /// into the local config so subsequent `identity publish` /
    /// `send` flows go over RFC 2136 UPDATE.
    Register {
        #[command(flatten)]
        common: RegisterArgs,
        /// DNS server to send UPDATEs to. Defaults to the node host.
        #[arg(long, value_name = "HOST")]
        dns_server: Option<String>,
        /// DNS port. Defaults to 53; use 5353 for dev nodes.
        #[arg(long, default_value_t = 53)]
        dns_port: u16,
    },
}

#[derive(Debug, ClapArgs)]
pub struct InitArgs {
    /// DMP username (e.g. `alice`).
    pub username: String,

    /// Mesh zone you publish under (e.g. `mesh.dnsmesh.io`).
    #[arg(long, value_name = "DOMAIN")]
    pub domain: String,
}

#[derive(Debug, Subcommand)]
pub enum IdentityCmd {
    /// Print this client's identity (username, pubkeys, DNS name).
    Show,

    /// Publish the signed identity record to DNS.
    Publish,

    /// Generate and publish a fresh pool of one-time prekeys.
    RefreshPrekeys {
        /// How many prekeys to generate.
        #[arg(long, default_value_t = 50)]
        count: u32,
        /// TTL applied to every published prekey TXT, in seconds.
        #[arg(long, default_value_t = 86_400)]
        ttl: u64,
    },

    /// Fetch and verify another user's identity record.
    Fetch {
        /// Address in the form `user@host`.
        address: String,
        /// Persist the fetched contact to the local store.
        #[arg(long)]
        add: bool,
    },

    /// Walk DNS UPDATE deletes against every record this identity
    /// published (identity, prekey RRset, all 10 mailbox slots,
    /// rotation/revocation RRset). Local state stays intact — for
    /// the "wipe everything" flow use `dnsmesh purge`.
    Unpublish {
        /// Skip the interactive confirmation. Required for non-
        /// interactive scripts.
        #[arg(long)]
        yes: bool,
    },

    /// Rotate the signing key. Publishes a co-signed RotationRecord
    /// from the old key to the new one, plus a fresh IdentityRecord
    /// for the new key. With `--reason compromise|lost_key` also
    /// publishes a self-signed RevocationRecord for the OLD key so
    /// rotation-aware receivers drop in-flight messages signed by
    /// the compromised key.
    Rotate {
        /// Why the rotation is happening. `routine` is periodic key
        /// refresh (no revocation). `compromise` and `lost_key` add a
        /// revocation publish; the wire-level `reason_code` differs.
        #[arg(long, value_enum, default_value_t = RotateReasonArg::Routine)]
        reason: RotateReasonArg,
        /// Env var holding the NEW passphrase. Defaults to prompting
        /// interactively. Same security caveats as
        /// `--insecure-passphrase-env`: the value is visible to
        /// anything that can read the process environment.
        #[arg(long, value_name = "ENV_VAR")]
        new_passphrase_env: Option<String>,
        /// TTL applied to the published rotation / revocation /
        /// identity TXT records (seconds).
        #[arg(long, default_value_t = 86_400)]
        ttl: u32,
        /// RotationRecord exp horizon (seconds from now). Default 1y.
        #[arg(long, default_value_t = 86_400 * 365)]
        exp_seconds: u64,
    },

    /// Publish a self-signed RevocationRecord for the CURRENT key.
    /// Use this when shutting an identity down without rotating to
    /// a new one. For "I lost my key, here's the new one" use
    /// `dnsmesh identity rotate --reason lost_key` instead — that
    /// publishes both the revocation AND a forward chain.
    Revoke {
        /// Reason embedded in the wire-level reason_code byte.
        /// `routine` is rejected (use `identity rotate` instead).
        #[arg(long, value_enum, default_value_t = RevokeReasonArg::Compromise)]
        reason: RevokeReasonArg,
        /// TTL applied to the published revocation TXT (seconds).
        #[arg(long, default_value_t = 86_400)]
        ttl: u32,
        /// Skip the interactive "are you sure" confirmation. Required
        /// for non-interactive scripts; standalone revoke is not
        /// reversible (you'd have to re-register the identity from
        /// scratch with a fresh SPK on the node).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, ClapArgs)]
pub struct PurgeArgs {
    /// Also walk DNS UPDATE deletes against every published record
    /// (identity, prekey RRset, mailbox slots, rotation RRset).
    /// Without --remote, only local state is wiped and the published
    /// records keep resolving until DNS TTLs expire.
    #[arg(long)]
    pub remote: bool,

    /// Skip the interactive confirmation. Required for non-
    /// interactive scripts. Combined with `--remote`, `--yes` will
    /// happily nuke a production identity — be deliberate.
    #[arg(long)]
    pub yes: bool,

    /// Wipe local state even if `--remote` failed to delete some
    /// records. By default a partial remote sweep aborts the local
    /// wipe so the operator still has the credentials needed to
    /// retry the DNS deletes — without this, you'd lose the
    /// passphrase + TSIG/HTTP token mid-flight while records stay
    /// live in DNS until TTL expiry.
    #[arg(long)]
    pub force_local_after_remote_failure: bool,
}

/// User-facing rotation reason flag. Mirrors the wire-level reason
/// codes in `dnsmesh_core::rotation::REASON_*`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RotateReasonArg {
    /// Periodic refresh; no revocation. Receivers without rotation-
    /// chain support keep trusting the old key until their cached
    /// IdentityRecord expires.
    Routine,
    /// Old key was disclosed. Publishes a revocation alongside the
    /// rotation so chain-aware receivers stop accepting messages
    /// signed by the old key immediately.
    Compromise,
    /// Old key was destroyed (lost passphrase, hardware failure).
    /// Same publish shape as `compromise`; the reason byte differs.
    LostKey,
}

/// User-facing standalone-revocation reason. `routine` is omitted —
/// a routine revocation has no use case (just rotate normally).
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RevokeReasonArg {
    Compromise,
    LostKey,
}

#[derive(Debug, Subcommand)]
pub enum IntroCmd {
    /// Show every quarantined intro awaiting review.
    List,

    /// Deliver one intro to the inbox without pinning the sender.
    Accept {
        /// `intro_id` from `dnsmesh intro list`.
        intro_id: i64,
    },

    /// Deliver the intro AND pin the sender as a trusted contact.
    Trust {
        /// `intro_id` from `dnsmesh intro list`.
        intro_id: i64,
        /// Sender's `user@host`. Required because the queue stores the
        /// signing key but not the home zone — the trust step verifies
        /// the address resolves to a published identity whose Ed25519
        /// key matches the quarantined manifest before pinning.
        #[arg(long, value_name = "ADDRESS")]
        address: String,
    },

    /// Drop the intro and add the sender to the local denylist so
    /// future manifests from the same key are dropped silently.
    Block {
        /// `intro_id` from `dnsmesh intro list`.
        intro_id: i64,
        /// Free-form local note for why this sender was blocked.
        #[arg(long, value_name = "TEXT", default_value = "")]
        note: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ContactsCmd {
    /// Manually pin a contact whose keys you already have.
    Add {
        /// Address in the form `user@host`.
        address: String,
        /// 64-char hex X25519 public key.
        #[arg(long, value_name = "HEX")]
        x25519: String,
        /// 64-char hex Ed25519 verifying key.
        #[arg(long, value_name = "HEX")]
        ed25519: String,
    },

    /// List every pinned contact.
    List,
}

#[derive(Debug, ClapArgs)]
#[allow(clippy::struct_excessive_bools)] // CLI flag struct; bools are the natural shape
pub struct SendArgs {
    /// Recipient as `user@host` or bare `user`. Required unless `-t` or `--recipient` is set.
    pub recipient: Option<String>,

    /// Read RFC 5322 from stdin and use the To: header as the recipient.
    /// sendmail-compat — wire `dnsmesh send -t` into mutt's `set sendmail`.
    #[arg(short = 't', long = "read-recipients")]
    pub read_recipients: bool,

    /// Recipient flag form (mutually exclusive with the positional argument).
    #[arg(long, value_name = "USER")]
    pub recipient_flag: Option<String>,

    /// Inline message body (mutually exclusive with stdin reading).
    #[arg(long, value_name = "TEXT")]
    pub message: Option<String>,

    // sendmail-compat flags accepted for tolerance with mutt / msmtp / git-send-email
    // and similar callers. We don't actually act on them — DMP doesn't have an
    // envelope-sender concept and we don't support the various sendmail modes.
    /// Envelope sender (sendmail compat — accepted and ignored).
    #[arg(short = 'f', long = "from", value_name = "ADDR", hide = true)]
    pub envelope_from: Option<String>,
    /// Ignore dots-on-a-line-by-themselves (sendmail compat — accepted and ignored).
    #[arg(short = 'i', hide = true)]
    pub ignore_dots: bool,
    /// "Background mode" / send-and-exit (sendmail compat — accepted and ignored).
    #[arg(long = "bm", hide = true)]
    pub background_mode: bool,
    /// "Initial mail submitter" (sendmail compat — accepted and ignored).
    #[arg(long = "oi", hide = true)]
    pub option_ignore_dots: bool,
    /// Catch-all positional addresses appended after `-t` by some MUAs;
    /// they are NOT used (the To: header drives recipient choice in -t mode).
    #[arg(value_name = "EXTRA_ADDR", hide = true, trailing_var_arg = true)]
    pub trailing: Vec<String>,

    /// Also publish a claim record at this provider zone so a
    /// recipient polling the zone can discover the message without
    /// walking the sender's home zone. Repeatable. Best-effort —
    /// claim publish failures don't block the underlying send.
    #[arg(long = "claim-via", value_name = "PROVIDER_ZONE")]
    pub claim_via: Vec<String>,
}

#[derive(Debug, ClapArgs)]
pub struct RecvArgs {
    /// Deliver decrypted messages into this Maildir (creates the cur/new/tmp tree if missing).
    #[arg(long, value_name = "PATH")]
    pub maildir: Option<PathBuf>,

    /// Do one poll pass and exit. Default behaviour.
    #[arg(long, conflicts_with = "watch")]
    pub once: bool,

    /// Poll repeatedly with `--interval` seconds between passes.
    #[arg(long)]
    pub watch: bool,

    /// Polling interval when `--watch` is set, in seconds.
    #[arg(long, default_value_t = 30, value_name = "SECONDS")]
    pub interval: u64,

    /// Also poll claim records at this provider zone. Repeatable.
    /// Each named zone is walked through the receive-via-claim path
    /// in addition to the standard own-zone-plus-pinned-zones walk.
    #[arg(long = "claim-via", value_name = "PROVIDER_ZONE")]
    pub claim_via: Vec<String>,
}
