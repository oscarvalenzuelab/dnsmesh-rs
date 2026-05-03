---
title: Mutt integration
layout: default
parent: Guide
nav_order: 3
---

# Mutt integration
{: .no_toc }

Wire `dnsmesh` into `mutt` / `neomutt` as a sendmail-compatible
transport so an existing mutt user can send and receive DMP
messages without leaving their MUA. The same pattern works for any
client that accepts a sendmail binary and a Maildir spool —
`alot`, `aerc`, `mblaze`, and the various `mu`/`notmuch` frontends.

1. TOC
{:toc}

## Why this works

The protocol's CLI surface is deliberately shaped to the sendmail
contract:

- `dnsmesh send -t` reads RFC 5322 from stdin and pulls the
  recipient list from the `To:` / `Cc:` / `Bcc:` headers — which
  is exactly what `mutt`'s `set sendmail` invokes.
- `dnsmesh recv --maildir <path>` writes decrypted messages into
  the standard `new/` / `cur/` / `tmp/` Maildir layout — which is
  exactly what `set spoolfile` reads from.

Result: mutt remains your composer and reader. `dnsmesh` is the
transport. No mutt patch needed.

## Prerequisites

Before wiring up mutt, finish the [Getting started]({{ site.baseurl }}/getting-started)
walkthrough end-to-end. You should have:

- A working `dnsmesh` binary on `$PATH` (or note its absolute path).
- An identity initialized in `~/.dmp/`.
- A publishing back-end configured (TSIG / Cloudflare / node-token).
- An identity record + prekey pool published.
- At least one contact pinned, so you have someone to send to.

Confirm with:

```sh
dnsmesh doctor
```

`doctor` prints a green check on every component when the
publishing path, the read path, and the keystore are all healthy.

## Minimal `~/.muttrc`

```muttrc
# --- Identity --------------------------------------------------------
set from         = "alice@dmp.example.com"
set realname     = "Alice"
set use_from     = yes
set use_envelope_from = yes

# --- Outbound: dnsmesh as the sendmail transport ---------------------
# `-t` makes dnsmesh read recipients from To:/Cc:/Bcc: headers in stdin
# (mutt's exact contract for `set sendmail`). Use the absolute path so
# the resolver order doesn't matter.
set sendmail     = "/usr/local/bin/dnsmesh send -t"
set sendmail_wait = 0

# --- Inbound: a Maildir spool dnsmesh recv writes into ---------------
set folder       = "$HOME/Mail/dmp"
set spoolfile    = "+inbox"
set mbox_type    = Maildir
set record       = "+sent"
set postponed    = "+drafts"
set trash        = "+trash"

mailboxes        = "+inbox" "+sent" "+drafts" "+trash"

# --- Some sane reading defaults -------------------------------------
set sort         = "threads"
set sort_aux     = "reverse-last-date-received"
set mark_old     = no
set wait_key     = no
```

If `dnsmesh` is not on the system `PATH` mutt can see (this is
common when mutt runs under launchd or systemd-user), use the
absolute path you tested with `which dnsmesh`.

## Receive loop

Mutt does not poll — it reads what's already in the spool. Run
`dnsmesh recv --watch` in a separate process so new messages land
in the Maildir as they arrive:

```sh
dnsmesh recv --maildir ~/Mail/dmp --watch --interval 30
```

In production, run this under a process supervisor of your choice:

### macOS (launchd)

`~/Library/LaunchAgents/io.dnsmesh.recv.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.dnsmesh.recv</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/dnsmesh</string>
    <string>recv</string>
    <string>--maildir</string>
    <string>/Users/alice/Mail/dmp</string>
    <string>--watch</string>
    <string>--interval</string>
    <string>30</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>DMP_PASSPHRASE_FILE</key>
    <string>/Users/alice/.dmp/passphrase</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/alice/Library/Logs/dnsmesh-recv.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/alice/Library/Logs/dnsmesh-recv.log</string>
</dict>
</plist>
```

```sh
launchctl load -w ~/Library/LaunchAgents/io.dnsmesh.recv.plist
```

### Linux (systemd --user)

`~/.config/systemd/user/dnsmesh-recv.service`:

```ini
[Unit]
Description=dnsmesh receive loop
After=network-online.target

[Service]
ExecStart=/usr/local/bin/dnsmesh recv --maildir %h/Mail/dmp --watch --interval 30
Environment=DMP_PASSPHRASE_FILE=%h/.dmp/passphrase
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now dnsmesh-recv.service
```

### cron (no daemon)

If you'd rather avoid a long-lived process, schedule a one-shot
poll on whatever cadence you like:

```cron
*/5 * * * * /usr/local/bin/dnsmesh recv --maildir $HOME/Mail/dmp >>/dev/null 2>&1
```

This trades latency (up to 5 minutes here) for not running a
process between polls.

## Sending: what mutt does and what dnsmesh sees

When you press `y` on the compose screen, mutt builds the full
RFC 5322 message — headers, body, MIME parts, attachments — and
pipes it to whatever you set as `sendmail`. With `dnsmesh send -t`:

1. dnsmesh parses the headers and pulls every address from `To:`,
   `Cc:`, and `Bcc:`.
2. For each recipient, it looks up the pinned contact and resolves
   it to a current signing key (walking the rotation chain if the
   contact has rotated and `rotation_chain_enabled` is set).
3. It encrypts the message body once per recipient (X25519 ECDH
   against a fresh ephemeral key + ChaCha20-Poly1305 AEAD).
4. It writes one signed manifest per recipient to that recipient's
   mailbox slot, with the chunked payload spread across as many
   chunk RRsets as needed.
5. The recipient's `recv` walks the slot, fetches the manifest,
   pulls the chunks, decrypts, verifies, and delivers.

The recipient must be pinned in your contact list before send
will succeed. If you `dnsmesh identity fetch <addr>` without
`--add`, send will fail with `unknown sender — fetch + pin first`.

## Headers added on receive

`dnsmesh recv --maildir` writes the decrypted message verbatim
into the Maildir, with these added headers so you can attribute
inside mutt without extra work:

| Header | Meaning |
|---|---|
| `X-DMP-Sender-SPK` | Hex of the sender's signing-public-key fingerprint. |
| `X-DMP-Sender-Address` | Pinned address of the sender (`alice@dmp.example.com`). |
| `X-DMP-Msg-Id` | Hex message identifier from the manifest. |
| `X-DMP-Timestamp` | Unix timestamp the manifest was signed at. |
| `X-DMP-Prekey-Id` | (When prekey-consumed) the prekey index that was consumed. |

If you want them visible in the index, add to your `.muttrc`:

```muttrc
unignore X-DMP-Sender-SPK X-DMP-Sender-Address X-DMP-Msg-Id \
         X-DMP-Timestamp X-DMP-Prekey-Id
```

## Attachments

Mutt's normal attachment workflow works as-is — attach via `a`,
let mutt build the multipart MIME message, and `dnsmesh send`
chunks the whole thing across as many DNS RRsets as needed. The
recipient sees a regular multipart message in their MUA; the
chunking is invisible above the wire format.

Bear in mind: every attachment byte rides through DNS as base64
in TXT records. Realistic limits on practical message size are
typically **a few megabytes**. For large attachments, ship them
out-of-band (link to an HTTPS host, use a separate file-transfer
tool) and put the reference in the message body.

## Replying

When you reply in mutt, mutt copies the original `From:` into
your reply's `To:` automatically. Because `recv` writes the
correct sender address into `From:` (resolving the
`X-DMP-Sender-Address` against your pinned contacts, not a
synthetic address), replies route to the right contact without
any further configuration.

If you ever see a reply addressed to a `dmp-<hex>@dmp.local`
synthetic address, that means the sender wasn't pinned at recv
time — fetch and pin them, and re-receive.

## Troubleshooting

### Send returns OK but nothing arrives

Run `dnsmesh doctor` on the **sender** side. The most common
cause is a broken `publish:` block — TSIG secret missing,
Cloudflare token expired, node-token revoked.

### Recv pulls nothing

Run `dig` against your mailbox slots directly:

```sh
for n in 0 1 2 3 4 5 6 7 8 9; do
  dig slot-$n.<recipient-id-prefix>.dmp.example.com TXT +short
done
```

Replace `<recipient-id-prefix>` with the first 16 hex chars of
`sha256(<your-username>)`. If `dig` returns the manifests but
`recv` doesn't surface them, the local replay cache may be
stale; `dnsmesh purge` (without `--remote`) and re-fetch.

### Mutt shows the wrong From: in replies

This was a real bug pre-strip; the fix lands the resolved
contact address into `From:` and `Reply-To:`. If you see
`dmp-<hex>@dmp.local` in a `From:`, the sender was not pinned
when `recv` delivered the message. Pin them and re-deliver:

```sh
dnsmesh identity fetch <sender@their-zone> --add
dnsmesh recv --maildir ~/Mail/dmp --reprocess
```

### Mutt's `set sendmail` exits non-zero on a partial recipient list

`dnsmesh send -t` exits non-zero if **any** recipient is
unreachable (no pinned contact, no resolvable identity, expired
prekey). Mutt treats that as a failed send and refuses to file the
message into `+sent`. Pin every recipient first; then resend.

### Mutt sends "address" through positional rather than -t

Older mutt configurations sometimes end up invoking sendmail with
positional addresses in addition to `-t`. `dnsmesh send -t`
accepts those positional addresses as a sendmail-style suppression
list (it ignores them, like classic sendmail did) — so the mutt
invocation works either way.

## Security considerations

- **The passphrase is the identity.** Long-lived `recv --watch`
  needs the passphrase available at every poll. Either export
  `DMP_PASSPHRASE` in the supervisor's environment, point
  `DMP_PASSPHRASE_FILE` at a 0400 file, or use a passphrase agent.
  The CLI refuses to read passphrase files with permissive mode
  bits.
- **Maildir on shared filesystems.** If `~/Mail/dmp` lives on a
  shared NFS mount or a synced cloud directory, decrypted
  plaintext is now on a shared surface. Either keep the Maildir
  on local-only storage or symlink it to an encrypted volume.
- **TSIG / API tokens.** The publishing credentials live in
  `~/.dmp/` at mode 0600. Don't dotfile-sync that directory to a
  cloud bucket without an extra encryption layer.
